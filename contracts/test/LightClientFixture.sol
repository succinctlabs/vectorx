pragma solidity 0.8.17;

import "forge-std/Common.sol";
import { NUM_AUTHORITIES } from "src/Constants.sol";
import { Groth16Proof, LightClient } from "src/LightClient.sol";

/// @notice Helper contract for parsing the JSON fixture, and converting them to the correct types.
/// @dev    The weird ordering here is because vm.parseJSON require alphabetical ordering of the
///         fields in the struct, and odd types with conversions are due to the way the JSON is
///         handled.
contract LightClientFixture is CommonBase {

    struct Initial {
        bytes32 startAuthoritySetCommitment;
        uint64 startAuthoritySetID;
        uint32 startHead;
        bytes32 startHeadHash;
    }

    struct Rotate {
        bytes[] encodedEventListProof;
        bytes[] newAuthoritySetIDProof;
        //Step step;
    }

    // Fields authoritySetID and merkleProof are for the AuthoritySetIDProof struct.
    struct Step {
        string[] a;
        bytes[] authoritySetIDProof;
        string[][] b;
        string[] c;
        uint32 head;
        bytes32 headHash;
        bytes32 previousStateRoot;
        bytes32 stateRoot;
        bytes32 updatedDataRootsCommitment;
    }

    function newLightClient(Initial memory initial)
        public
        returns (LightClient)
    {
        return new LightClient(
            initial.startHead,
            initial.startHeadHash,
            initial.startAuthoritySetID,
            initial.startAuthoritySetCommitment
        );
    }

    function convertToGroth16Proof(Step memory step) public pure returns (Groth16Proof memory) {
        uint256[2] memory a = [strToUint(step.a[0]), strToUint(step.a[1])];
        uint256[2][2] memory b = [
            [strToUint(step.b[0][1]), strToUint(step.b[0][0])],
            [strToUint(step.b[1][1]), strToUint(step.b[1][0])]
        ];
        uint256[2] memory c = [strToUint(step.c[0]), strToUint(step.c[1])];

        return Groth16Proof(a, b, c);
    }

    function strToUint(string memory str) internal pure returns (uint256 res) {
        for (uint256 i = 0; i < bytes(str).length; i++) {
            if ((uint8(bytes(str)[i]) - 48) < 0 || (uint8(bytes(str)[i]) - 48) > 9) {
                revert();
            }
            res += (uint8(bytes(str)[i]) - 48) * 10 ** (bytes(str).length - i - 1);
        }

        return res;
    }
}
