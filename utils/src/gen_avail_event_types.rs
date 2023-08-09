use std::any::TypeId;
use std::collections::HashMap;
use std::io::{Cursor, Read};

use avail_subxt::build_client;
use codec::{Decode, IoReader};
use enum_extract::extract;
use itertools::Itertools;
use scale_info::TypeDef;
use scale_info::interner::UntrackedSymbol;
use subxt::Metadata;
//use subxt::{ext::{sp_runtime::scale_info::{TypeDef, interner::UntrackedSymbol}}, Metadata};
//use subxt::ext::sp_runtime::scale_info::TypeDefPrimitive::{ Bool, U8, U16, U32, U64, U128, I8, I16, I32, I64, I128 };


#[derive(Debug, Clone)]
enum Chunk {
    ConstantSize(u32),
    Compact,
    Sequence(Vec<Chunk>),
}

fn add_constant_size(size: u32, type_chunk_sizes: &mut Vec<Chunk>) {
    if type_chunk_sizes.len() > 0 {
        match type_chunk_sizes.last_mut().unwrap() {
            Chunk::ConstantSize(s) => {
                *s += size;
            }
            _ => {
                type_chunk_sizes.push(Chunk::ConstantSize(size));
            }
        }
    } else {
        type_chunk_sizes.push(Chunk::ConstantSize(size));
    }
}

fn get_type_size<'b>(md: &Metadata, substrate_type: &'b UntrackedSymbol<TypeId>, type_chunk_sizes: &mut Vec<Chunk>) {
    let td = md.runtime_metadata().types.resolve(substrate_type.id).unwrap();

    match &td.type_def {
        TypeDef::Composite(c) => {
            for f in c.fields.iter() {
                get_type_size(md, &f.ty, type_chunk_sizes);
            }
        }

        TypeDef::Variant(v) => {
            // First byte is the Variant index
            add_constant_size(1, type_chunk_sizes);
            for v in v.variants.iter() {
                for f in v.fields.iter() {
                    get_type_size(md, &f.ty, type_chunk_sizes);
                }
            }
        }

        TypeDef::Sequence(s) => {
            let mut sequence_chunks = Vec::new();
            get_type_size(md, &s.type_param, &mut sequence_chunks);

            type_chunk_sizes.push(Chunk::Sequence(sequence_chunks));
        }

        TypeDef::Array(a) => {
            let array_len = a.len;
            let mut array_element_size = Vec::new();
            get_type_size(md, &a.type_param,  &mut array_element_size);
            assert!(array_element_size.len() == 1);
            assert!(matches!(array_element_size[0], Chunk::ConstantSize {..}));

            add_constant_size(array_len * extract!(Chunk::ConstantSize(_), array_element_size[0]).unwrap(), type_chunk_sizes);
        }

        TypeDef::Tuple(t) => {
            for f in t.fields.iter() {
                get_type_size(md, &f, type_chunk_sizes);
            }
        }

        TypeDef::Primitive(p) => {
            let primitive_size:u32;
            match p {
                    scale_info::TypeDefPrimitive::Bool => {
                        primitive_size = 1;
                    }
                    scale_info::TypeDefPrimitive::U8 => {
                        primitive_size = 1;
                    }
                    scale_info::TypeDefPrimitive::U16 => {
                        primitive_size =  2;
                    }
                    scale_info::TypeDefPrimitive::U32 => {
                        primitive_size = 4;
                    }
                    scale_info::TypeDefPrimitive::U64 => {
                        primitive_size = 8;
                    }
                    scale_info::TypeDefPrimitive::U128 => {
                        primitive_size = 16;
                    }
                    scale_info::TypeDefPrimitive::I8 => {
                        primitive_size = 1;
                    }
                    scale_info::TypeDefPrimitive::I16 => {
                        primitive_size = 2;
                    }
                    scale_info::TypeDefPrimitive::I32 => {
                        primitive_size = 4;
                    }
                    scale_info::TypeDefPrimitive::I64 => {
                        primitive_size = 8;
                    }
                    scale_info::TypeDefPrimitive::I128 => {
                        primitive_size = 16;
                    }
                    _ => {
                        panic!("\t\tunhandled primitive type of {:?}", p);
                    }
                }

            add_constant_size(primitive_size, type_chunk_sizes);
        }

        TypeDef::Compact(_) => {
            type_chunk_sizes.push(Chunk::Compact);
        }

        _ => { println!("Unhandled type {:?}", td.type_def) }
    }
}

async fn get_type_chunks() -> HashMap<u8, HashMap<u8, Vec<Chunk>>>{
    let url: &str = "wss://kate.avail.tools:443/ws";

    let c = build_client(url, false).await.unwrap();
    let md = c.metadata();

    let mut avail_event_type_chunks = HashMap::new();

    let pallets = &md.runtime_metadata().pallets;
    for p in pallets.iter() {
        println!("pallet is {:?}", p.name);
        println!("pallet index is {:?}", p.index);
        let mut pallet_event_type_chunks = HashMap::new();

        if p.event.is_some() {
            let events = md.runtime_metadata().types.resolve(p.event.as_ref().unwrap().ty.id);

            for e in events.iter() {
                let td = &e.type_def;

                match td {
                    TypeDef::Variant(v) => {
                        for v in v.variants.iter() {
                            println!("\tEvent {:?} has index of {:?}", v.name, v.index);
                            let mut type_chunk_sizes = Vec::new();

                            // Seems like there are an extra 4 bytes in front of events for System.ExtrinsicSuccess events
                            // TODO:  Check if this is true for other System pallets
                            if p.index == 0 && v.index == 0 {
                                add_constant_size(4, &mut type_chunk_sizes);
                            }

                            for f in v.fields.iter() {
                                get_type_size(&md, &f.ty, &mut type_chunk_sizes);
                            }

                            println!("\tEvent {:?} has type_chunk_sizes of {:?}\n\n\n", v.name, type_chunk_sizes);
                            pallet_event_type_chunks.insert(v.index, type_chunk_sizes);
                        }                
                    }

                    _ => { panic!("Unexpected td of {:?}", td) }
                }

            }

            avail_event_type_chunks.insert(p.index, pallet_event_type_chunks);
            println!("\n\n\n");
        }
    }

    avail_event_type_chunks
}


fn read_chunk<R: std::io::Read>(chunk: &Chunk, io_reader: &mut IoReader<R>) {
    match chunk {
        Chunk::ConstantSize(size) => {
            let mut buf: Vec<u8> = vec![0; *size as usize];
            io_reader.0.read_exact(buf.as_mut_slice()).unwrap();
        }

        Chunk::Sequence(sequence_chunks) => {
            let sequence_length = codec::Compact::<u128>::decode(io_reader).unwrap();
            for _ in 0..sequence_length.0 {
                for inner_chunk in sequence_chunks.iter() {
                    read_chunk(inner_chunk, io_reader);
                }
            }
        }

        Chunk::Compact => {
            let _ = codec::Compact::<u128>::decode(io_reader).unwrap();
        }
    }
}


#[tokio::main]
pub async fn main() {
    let contract_template = "
contract AvailEventScaleChunks {
    enum CHUNK_TYPE{ CONSTANT_SIZE, COMPACT, SEQUENCE }

    struct Chunk {
        CHUNK_TYPE chunk_type;
        uint32 size;
        Chunk[] sequence_chunks;
    }

    mapping(uint8 => mapping(uint8 => Chunk[])) event_chunks;

    constructor() {
{CONSTRUCTOR_CODE}
    }
}";

    let type_chunks = get_type_chunks().await;
    let mut constructor_code = "".to_owned();
    for pallet_idx in type_chunks.keys().sorted() {
        for event_idx in type_chunks[pallet_idx].keys().sorted() {
            let event_type_chunks = &type_chunks[pallet_idx][event_idx];

            for (i, chunk) in event_type_chunks.iter().enumerate() {
                constructor_code.push_str(format!("        event_chunks[{}][{}].push();\n", pallet_idx, event_idx).as_str());
                match chunk {
                    Chunk::ConstantSize(size) => {
                        constructor_code.push_str(format!("        event_chunks[{}][{}][{}].chunk_type = CHUNK_TYPE.CONSTANT_SIZE;\n", pallet_idx, event_idx, i).as_str());
                        constructor_code.push_str(format!("        event_chunks[{}][{}][{}].size = {};\n", pallet_idx, event_idx, i, size).as_str());
                    }
            
                    Chunk::Compact => {
                        constructor_code.push_str(format!("        event_chunks[{}][{}][{}].chunk_type = CHUNK_TYPE.COMPACT;\n", pallet_idx, event_idx, i).as_str());
                    }
            
                    Chunk::Sequence(sequence_chunks) => {
                        constructor_code.push_str(format!("        event_chunks[{}][{}][{}].chunk_type = CHUNK_TYPE.SEQUENCE;\n", pallet_idx, event_idx, i).as_str());
                        for (j, sequence_chunk) in sequence_chunks.iter().enumerate() {
                            constructor_code.push_str(format!("        event_chunks[{}][{}][{}].sequence_chunks.push();\n", pallet_idx, event_idx, i).as_str());
                            match sequence_chunk {
                                Chunk::ConstantSize(size) => {
                                    constructor_code.push_str(format!("        event_chunks[{}][{}][{}].sequence_chunks[{}].chunk_type = CHUNK_TYPE.CONSTANT_SIZE;\n", pallet_idx, event_idx, i, j).as_str());
                                    constructor_code.push_str(format!("        event_chunks[{}][{}][{}].sequence_chunks[{}].size = {};\n", pallet_idx, event_idx, i, j, size).as_str());
                                }
            
                                Chunk::Compact => {
                                    constructor_code.push_str(format!("        event_chunks[{}][{}][{}].sequence_chunks[{}].chunk_type = CHUNK_TYPE.COMPACT;\n", pallet_idx, event_idx, i, j).as_str());
                                }
            
                                Chunk::Sequence(inner_sequence_chunks) => {
                                    constructor_code.push_str(format!("        event_chunks[{}][{}][{}].sequence_chunks[{}].chunk_type = CHUNK_TYPE.SEQUENCE;\n", pallet_idx, event_idx, i, j).as_str());
            
                                    for (k, inner_sequence_chunk) in inner_sequence_chunks.iter().enumerate() {
                                        constructor_code.push_str(format!("        event_chunks[{}][{}][{}].sequence_chunks[{}].sequence_chunks.push();\n", pallet_idx, event_idx, i, j).as_str());
                                        match inner_sequence_chunk {
                                            Chunk::ConstantSize(size) => {
                                                constructor_code.push_str(format!("        event_chunks[{}][{}][{}].sequence_chunks[{}].sequence_chunks[{}].chunk_type = CHUNK_TYPE.CONSTANT_SIZE;\n", pallet_idx, event_idx, i, j, k).as_str());
                                                constructor_code.push_str(format!("        event_chunks[{}][{}][{}].sequence_chunks[{}].sequence_chunks[{}].size = {};\n", pallet_idx, event_idx, i, j, k, size).as_str());
                                            }
            
                                            Chunk::Compact => {
                                                constructor_code.push_str(format!("        event_chunks[{}][{}][{}].sequence_chunks[{}].sequence_chunks[{}].chunk_type = CHUNK_TYPE.COMPACT;\n", pallet_idx, event_idx, i, j, k).as_str());
                                            }
            
                                            Chunk::Sequence(_) => {
                                                panic!("Nested sequence of depth 2 is not supported");
                                            }
                                        }
                                    }            
                                }
                            }
                        }
                    }
                }            
            }
        }
    }

    println!("contract_template: {}", contract_template.replace("{CONSTRUCTOR_CODE}", constructor_code.as_str()));
}


#[tokio::test]
async fn test_nested_sequence() {
    // pallet is "ImOnline"(20)
    // event is "SomeOffline"(2)

    let type_chunks = get_type_chunks().await;

    let pallet_idx = 20;
    let event_idx = 2;
    let event_data: [u8; 98] = [4, 84, 86, 92, 68, 217, 86, 27, 84, 33, 157, 68, 32, 5, 81, 171, 48, 223, 54, 187, 202, 12, 215, 119, 153, 24, 104, 224, 147, 68, 199, 15, 117, 27, 149, 141, 163, 204, 231, 204, 4, 2, 103, 1, 23, 142, 125, 100, 45, 45, 27, 139, 81, 54, 4, 164, 206, 101, 103, 123, 218, 213, 223, 55, 70, 58, 88, 59, 44, 12, 216, 111, 45, 155, 160, 151, 213, 227, 52, 12, 46, 12, 15, 87, 245, 255, 17, 27, 7, 16, 63, 159, 186, 177, 121, 176, 48, 1];
    let event_data_cursor = Cursor::new(&event_data);
    let mut io_reader = IoReader(event_data_cursor);

    // Retrieve the chunk definition for the event
    let chunks = type_chunks.get(&pallet_idx).unwrap().get(&event_idx).unwrap();

    println!("ImOnline.Someoffline event has chunks of {:?}", chunks);

    for c in chunks.iter() {
        read_chunk(c, &mut io_reader)
    }
}
