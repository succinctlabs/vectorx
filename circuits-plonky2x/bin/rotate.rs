


// 

inputs: 
- current_authority_set_hash
- current_authority_set_id
- epoch_end_block_number

circuit:
- get header bytes of epoch_end_block_number (EncodedHeaderVariable)
- decode the header bytes (HeaderVariable)
- verify HeaderVariable.block_number == epoch_end_block_number
- witness the start_idx, end_idx of the desired log 
- witness number of active validators from the log 
- witness the ArrayVariablew<ValidatorVariable, MAX_NUM_VALIDATORS>
- log_bytes = builder.get_subarray(header_bytes, start_idx, end_idx)
- log_bytes[0] == 04
- log_bytes[1...5] = 46524e4b
- log_bytes[6...10]  = ??

- for i in 0...MAX_NUM_VALIDATORS {
    cursor = builder.add(cursor, validator_active * (32 + 8))
    if i <= num_active_validators {

    }
}

log_bytes[cursor:cursor+4] == 0x000000
cursor+4 === end_idx


builder.verify_simple_justification(header, current_authority_set_id, current_authority_set_hash)