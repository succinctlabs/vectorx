use std::any::TypeId;

use avail_subxt::build_client;
use subxt::{ext::{sp_runtime::scale_info::{TypeDef, interner::UntrackedSymbol}}, Metadata};
use subxt::ext::sp_runtime::scale_info::TypeDefPrimitive::{ Bool, U8, U16, U32, U64, U128, I8, I16, I32, I64, I128 };

#[derive(Debug)]
struct ChunkSize {
    size: u32,
    is_seq: bool,
}

fn get_type_size<'b>(md: &Metadata, substrate_type: &'b UntrackedSymbol<TypeId>, type_chunk_sizes: &mut Vec<ChunkSize>) {
    let td = md.runtime_metadata().types.resolve(substrate_type.id).unwrap();

    match &td.type_def {
        TypeDef::Composite(c) => {
            for f in c.fields.iter() {
                get_type_size(md, &f.ty, type_chunk_sizes);
            }
        }

        TypeDef::Variant(v) => {
            for v in v.variants.iter() {
                for f in v.fields.iter() {
                    get_type_size(md, &f.ty, type_chunk_sizes);
                }
            }
        }

        TypeDef::Sequence(s) => {
            // Assert we are not already in a sequence
            if type_chunk_sizes.len() > 0 {
                assert!(type_chunk_sizes.last().unwrap().is_seq == false);
            }

            let mut seq_element_size = Vec::new();
            seq_element_size.push(ChunkSize{size: 0, is_seq: true});
            get_type_size(md, &s.type_param, &mut seq_element_size);
            assert!(seq_element_size.len() == 1 && seq_element_size[0].is_seq == true);

            type_chunk_sizes.append(&mut seq_element_size);
        }

        TypeDef::Array(a) => {
            let array_len = a.len;
            let mut array_element_size = Vec::new();
            get_type_size(md, &a.type_param,  &mut array_element_size);
            assert!(array_element_size.len() == 1 && array_element_size[0].is_seq == false);

            // Get the last chunk size obj
            if type_chunk_sizes.len() == 0 {
                type_chunk_sizes.push(ChunkSize{size: 0, is_seq: false})
            }

            let last_chunk_size = type_chunk_sizes.last_mut().unwrap();

            (*last_chunk_size).size += array_len * array_element_size[0].size;
        }

        TypeDef::Tuple(t) => {
            for f in t.fields.iter() {
                get_type_size(md, &f, type_chunk_sizes);
            }
        }

        TypeDef::Primitive(p) => {
            // Get the last chunk size obj
            if type_chunk_sizes.len() == 0 {
                type_chunk_sizes.push(ChunkSize{size: 0, is_seq: false})
            }

            let last_chunk_size = type_chunk_sizes.last_mut().unwrap();

            match p {
                    Bool => {
                        last_chunk_size.size += 1;
                    }
                    U8 => {
                        last_chunk_size.size += 1;
                    }
                    U16 => {
                        last_chunk_size.size += 2;
                    }
                    U32 => {
                        last_chunk_size.size += 4;
                    }
                    U64 => {
                        last_chunk_size.size += 8;
                    }
                    U128 => {
                        last_chunk_size.size += 16;
                    }
                    I8 => {
                        last_chunk_size.size += 1;
                    }
                    I16 => {
                        last_chunk_size.size += 2;
                    }
                    I32 => {
                        last_chunk_size.size += 4;
                    }
                    I64 => {
                        last_chunk_size.size += 8;
                    }
                    I128 => {
                        last_chunk_size.size += 16;
                    }
                    _ => {
                        println!("\t\tprimitive type is {:?}", p);
                    }
                }
        }

        /*
        TypeDef::Compact(c) => {
            *is_var_sized = true;
            return 0;
        }
        */

        _ => { println!("Unhandled type {:?}", td.type_def) }
    }
}

#[tokio::main]
pub async fn main() {
    let url: &str = "wss://testnet.avail.tools:443/ws";

    let c = build_client(url).await.unwrap();

    let md = c.metadata();

    let pallets = &md.runtime_metadata().pallets;

    for p in pallets.iter() {
        println!("pallet is {:?}", p.name);
        println!("pallet index is {:?}", p.index);
        if p.event.is_some() {
            let events = md.runtime_metadata().types.resolve(p.event.as_ref().unwrap().ty.id);

            for e in events.iter() {
                let td = &e.type_def;

                match td {
                    TypeDef::Variant(v) => {
                        for v in v.variants.iter() {
                            let mut type_chunk_sizes = Vec::new();
                            for f in v.fields.iter() {
                                get_type_size(&md, &f.ty, &mut type_chunk_sizes);
                            }

                            println!("\tEvent {:?} has type_chunk_sizes of {:?}", v.name, type_chunk_sizes);
                        }                
                    }

                    _ => { panic!("Unexpected td of {:?}", td) }
                }
            }

            println!("\n\n\n");
        }
    }
}