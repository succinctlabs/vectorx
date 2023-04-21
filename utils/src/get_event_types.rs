use std::any::TypeId;

use avail_subxt::build_client;
use subxt::{ext::{sp_runtime::scale_info::{TypeDef, interner::UntrackedSymbol}}, Metadata};
use subxt::ext::sp_runtime::scale_info::TypeDefPrimitive::{ Bool, U8, U16, U32, U64, U128, I8, I16, I32, I64, I128 };

fn get_type_size<'b>(md: &Metadata, substrate_type: &'b UntrackedSymbol<TypeId>) -> u32 {
    let mut field_size = 0_u32;

    let td = md.runtime_metadata().types.resolve(substrate_type.id).unwrap();

    match &td.type_def {
        TypeDef::Composite(c) => {
            for f in c.fields.iter() {
                field_size += get_type_size(md, &f.ty);
            }
        }

        TypeDef::Variant(v) => {
            for v in v.variants.iter() {
                for f in v.fields.iter() {
                    field_size += get_type_size(md, &f.ty);
                }
            }
        }
        /*
        TypeDef::Sequence(s) => {
            println!("\t\tsequence type is {:?}", s.name);
            output_event_type(md, &s.fields);
        }
        */

        TypeDef::Array(a) => {
            let array_len = a.len;
            let element_size = get_type_size(md, &a.type_param);

            field_size += array_len * element_size;
        }

        /*
        TypeDef::Tuple(t) => {
            println!("\t\ttuple type is {:?}", t.name);
            output_event_type(md, &t.fields);
        }*/
        TypeDef::Primitive(p) => {
            match p {
                    Bool => {
                        field_size += 1;
                    }
                    U8 => {
                        field_size += 1;
                    }
                    U16 => {
                        field_size += 2;
                    }
                    U32 => {
                        field_size += 4;
                    }
                    U64 => {
                        field_size += 8;
                    }
                    U128 => {
                        field_size += 16;
                    }
                    I8 => {
                        field_size += 1;
                    }
                    I16 => {
                        field_size += 2;
                    }
                    I32 => {
                        field_size += 4;
                    }
                    I64 => {
                        field_size += 8;
                    }
                    I128 => {
                        field_size += 16;
                    }
                    _ => {
                        println!("\t\tprimitive type is {:?}", p);
                    }
                }
        }
        /*
        TypeDef::Compact(c) => {
            println!("\t\tcompact type is {:?}", c.name);
            output_event_type(md, &c.fields);
        }
        TypeDef::BitSequence(b) => {
            println!("\t\tbit sequence type is {:?}", b.name);
            output_event_type(md, &b.fields);
        }
        */
        _ => {
            println!("\t\ttype is {:?}", td.type_def);
        }
    }

    field_size
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
                            let mut type_size = 0_u32;
                            for f in v.fields.iter() {
                                type_size += get_type_size(&md, &f.ty);
                            }
                            println!("\tvariant index is {:?} and size is {:?}", v.index, type_size);
                        }                
                    }

                    _ => { panic!("Unexpected td of {:?}", td) }
                }
            }

            println!("\n\n\n");
        }
    }
}