// fn rotate(authority_set_hash, end_of_epoch_header) -> AuthoritySetHash {
//     target_hash = verify_simple_justification(end_of_epoch_header, authority_set_hash) // get authority set, prove matches authority_set_hash, verify(target_hash, authority_set), verify(target_hash.block = target_block)

//     // witness the authoriy set members in the event ogs
//     // poseidon_hash(authority_set_members)
//     // return hash
// }

fn verify_simple_justification(
    target_block_decoded: DecodedBlock,
    target_hash: Hash,
    authority_set_id: u32,
    authority_set_hash: Hash,
    authority_set_members: Vec<AuthoritySetMember>,
) {
    // Assume that target_block and target_hash already appropriately linked
    check_correct_authority_set(authority_set_hash, authority_set_members);
    check_quorum_signed(target_block_decoded.number, target_hash, authority_set_id, authority_set_members);
}

fn update_data_committment(trusted_block_number: u32, trusted_hash: Hash, authority_set_id: u32, authority_set_hash: Hash, target_block_number: u32) -> (Hash, Hash) {
    let all_raw_headers = hint_get_headers(trusted_block, target_block_number); // this is a hint
    let decoded_headers = constraint_decode_headers(all_raw_headers);
    let block_hashes = constraint_hash_headers(all_raw_headers);

    constraint_block_number(decoded_headers[0], trusted_block_number);
    assert_eq(block_hashes[0] == trusted_hash); // this is redundant with the above line so we can pick one
    constraint_block_number(decoded_headers[-1], target_block_number);

    let authority_set_members = hint_get_authority_set(authority_set_id);
    verify_simple_justification(
        decoded_headers[-1],
        block_hashes[-1],
        authority_set_id, 
        authority_set_hash,
        authority_set_members
    );

    verify_sequential_header_chain(decoded_headers, block_hashes);
    data_root_hash = hash_data_root(decoded_headers.iter().map((x) => x.data_root));
    return block_hashes[-1], data_root_hash
}
