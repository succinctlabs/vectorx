// fn rotate(authority_set_hash, end_of_epoch_header) -> AuthoritySetHash {
//     target_hash = verify_simple_justification(end_of_epoch_header, authority_set_hash) // get authority set, prove matches authority_set_hash, verify(target_hash, authority_set), verify(target_hash.block = target_block)

//     // witness the authoriy set members in the event ogs
//     // poseidon_hash(authority_set_members)
//     // return hash
// }

// fn update_data_committment(start_block, start_hash, target_block, authority_set_hash) -> target_hash, data_hash(start_block, target_block) {
//     target_hash = verify_simple_justification(target_bock, authority_set_hash) // get authority set, prove matches authority_set_hash, verify(target_hash, authority_set), verify(target_hash.block = target_block)

//     all_headers = [header_start, ..., header_end]
//     hashes = [hash_start, ..., hash_end]
//     decoding = [decoded_start, ..., decoded_end]

//     check_links(all_headers, hashes, decoding) // verify that all headers are linked correctly
//     all_headers[0] == start_hash
//     all_headers[-1] == target_hash

//     data_root_hash = hash_data_root(decoding.iter().map((x) => x.data_root));
//     return target_hash, data_root_hash
// }
