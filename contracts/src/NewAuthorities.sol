import {ScaleCodec} from "solidity-merkle-trees/src/trie/substrate/ScaleCodec.sol";

struct Authority {
    bytes32 eddsa_pub_key;
    uint64 weight;
}

/// @title New Authorities
/// @author Succinct Labs
/// @notice Will extract the new authority set from a scale encoded event list
contract NewAuthorities {
    constructor() {}

    function decodeEventList(bytes calldata encoded_events_list) external returns (Authority[] memory) {
        uint256 cursor = 0;

        // First get the length of the encoded_events_list
        (uint256 num_events, uint8 num_events_mode) = ScaleCodec.decodeUintCompact(encoded_events_list);

        // Kind of a hack
        cursor += (num_events_mode + 1);

        Authority[] memory authorities = new Authority[](10);

        uint8 phase;
        uint8 pallet_index;
        uint8 event_index;

        // Parse the scale encoded events
        for (uint256 i = 0; i < num_events; i++) {
            // First element is the Phase enum value (0 - ApplyExtrinsic, 1 - Finalization, 2 - Initialization)
            phase = uint8(encoded_events_list[cursor]);
            cursor++;

            // Second element is the pallet_index
            pallet_index = uint8(encoded_events_list[cursor]);
            cursor++;

            // Third element is the event_index
            event_index = uint8(encoded_events_list[cursor]);
            cursor++;

            // Decode the actual event
            if (phase == 1 && pallet_index == 17 && event_index == 0) {
                // This is the NewAuthorities event

                // The next element is the length of the encoded new authorities list
                (uint256 num_authorities, uint8 num_authorities_mode) = ScaleCodec.decodeUintCompact(encoded_events_list[cursor:]);

                // Kind of a hack
                cursor += (num_authorities_mode + 1);

                // Parse the scale encoded authorities
                for (uint256 j = 0; j < num_authorities; j++) {
                    // First 32 bytes is the eddsa pub key
                    authorities[j] = Authority(bytes32(encoded_events_list[cursor:cursor + 32]), ScaleCodec.decodeUint64(encoded_events_list[cursor + 32:cursor + 40]));
                    cursor += 40;
                }
            } else {
                require(false, "Got a non-NewAuthorities event");
            }

            // There is a 0 value byte at the end of each event
            require(uint8(encoded_events_list[cursor]) == 0, "last byte of event is not 0");
            cursor++;
        }

        require(cursor == encoded_events_list.length, "Did not parse all of the encoded events bytes");

        return authorities;
    }
}