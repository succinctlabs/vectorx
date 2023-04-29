pragma solidity 0.8.17;

import "forge-std/Vm.sol";
import "forge-std/console.sol";
import "forge-std/Test.sol";

import {AvailLightClient,
        AuthoritySetProof,
        EventListProof,
        LightClientStep,
        LightClientFinalize,
        LightClientRotate,
        NUM_AUTHORITIES} from "src/AvailLightClient.sol";
import {AvailLightClientFixture} from "test/AvailLightClient/AvailLightClientFixture.sol";
import {Strings} from "openzeppelin-contracts/utils/Strings.sol";

contract AvailLightClientTest is Test, AvailLightClientFixture {
    uint256 constant FIXTURE_BLOCK_START = 576727;
    uint256 constant FIXTURE_BLOCK_END = 576727;

    Fixture[] fixtures;

    function setUp() public {
        // read all fixtures from entire directory
        string memory root = vm.projectRoot();
        for (uint256 i = FIXTURE_BLOCK_START; i <= FIXTURE_BLOCK_END; i++) {
            uint256 blockNum = i;

            string memory filename = string.concat("block", Strings.toString(blockNum));
            string memory path =
                string.concat(root, "/test/AvailLightClient/fixtures/", filename, ".json");
            try vm.readFile(path) returns (string memory file) {
                bytes memory parsed = vm.parseJson(file);
                fixtures.push(abi.decode(parsed, (Fixture)));
            } catch {
                continue;
            }
        }

        vm.warp(9999999999999);
    }

    function test_SetUp() public {
        assertTrue(fixtures.length > 0);
    }

    function test_AvailLightClientConstruction() public {
        AvailLightClient lc = newAvailLightClient(fixtures[0].initial);

        Initial memory initial = fixtures[0].initial;

        assertTrue(lc.START_CHECKPOINT_BLOCK_NUMBER() == initial.startCheckpointBlockNumber);
        assertTrue(lc.head() == initial.startCheckpointBlockNumber);
        assertTrue(lc.finalizedHead() == initial.startCheckpointBlockNumber);
        assertTrue(lc.headerRoots(initial.startCheckpointBlockNumber) == initial.startCheckpointHeaderRoot);
        assertTrue(lc.executionStateRoots(initial.startCheckpointBlockNumber) == initial.startCheckpointExecutionRoot);

        for (uint16 i = 0; i < NUM_AUTHORITIES; i++) {
            assertTrue(lc.authorityPubKeys(initial.startCheckpointAuthoritySetID, i) == initial.authorityPubKeys[i]);
        }
    }

    function test_AvailLightClientStep() public {
        AvailLightClient lc = newAvailLightClient(fixtures[0].initial);
        LightClientStep memory step;
        
        step.blockNumber = fixtures[0].step.blockNumber;
        step.executionStateRoot = fixtures[0].step.executionStateRoot;
        step.headerRoot = fixtures[0].step.headerRoot;
        step.parentRoot = fixtures[0].step.parentRoot;

        lc.step(step);

        assertTrue(lc.head() == step.blockNumber);
        assertTrue(lc.finalizedHead() != step.blockNumber);
        assertTrue(lc.headerRoots(step.blockNumber) == step.headerRoot);
        assertTrue(lc.executionStateRoots(step.blockNumber) == step.executionStateRoot);
    }

    function test_AvailLightClientStep_badParentRoot() public {
        string memory path = string.concat(
            vm.projectRoot(), "/test/AvailLightClient/fixtures/block576727_bad1.json"
        );
        bytes memory parsed = vm.parseJson(vm.readFile(path));
        Fixture memory fixture = abi.decode(parsed, (Fixture));

        AvailLightClient lc = newAvailLightClient(fixture.initial);
        LightClientStep memory step;
        
        step.blockNumber = fixture.step.blockNumber;
        step.executionStateRoot = fixture.step.executionStateRoot;
        step.headerRoot = fixture.step.headerRoot;
        step.parentRoot = fixture.step.parentRoot;

        vm.expectRevert();
        lc.step(step);
    }

    function test_AvailLightClientStep_badBlockNumber() public {
        string memory path = string.concat(
            vm.projectRoot(), "/test/AvailLightClient/fixtures/block576727_bad2.json"
        );
        bytes memory parsed = vm.parseJson(vm.readFile(path));
        Fixture memory fixture = abi.decode(parsed, (Fixture));

        AvailLightClient lc = newAvailLightClient(fixture.initial);
        LightClientStep memory step;
        
        step.blockNumber = fixture.step.blockNumber;
        step.executionStateRoot = fixture.step.executionStateRoot;
        step.headerRoot = fixture.step.headerRoot;
        step.parentRoot = fixture.step.parentRoot;

        vm.expectRevert();
        lc.step(step);
    }

    function test_AvailLightClientStepAndFinalize() public {
        AvailLightClient lc = newAvailLightClient(fixtures[0].initial);
        LightClientStep memory step;

        step.blockNumber = fixtures[0].step.blockNumber;
        step.executionStateRoot = fixtures[0].step.executionStateRoot;
        step.headerRoot = fixtures[0].step.headerRoot;
        step.parentRoot = fixtures[0].step.parentRoot;

        lc.step(step);

        assertTrue(lc.head() == step.blockNumber);
        assertTrue(lc.finalizedHead() != step.blockNumber);
        assertTrue(lc.headerRoots(step.blockNumber) == step.headerRoot);
        assertTrue(lc.executionStateRoots(step.blockNumber) == step.executionStateRoot);

        LightClientFinalize memory finalize;

        finalize.blockNumber = fixtures[0].finalize.blockNumber;
        finalize.headerRoot = fixtures[0].finalize.headerRoot;
        finalize.authoritySetProof = AuthoritySetProof({
            authoritySetID: fixtures[0].finalize.authoritySetID,
            merkleProof: fixtures[0].finalize.merkleProof
        });
        lc.finalize(finalize);

        assertTrue(lc.finalizedHead() == finalize.blockNumber);
    }

    function test_AvailLightClientStepFinalizeRotate() public {
        AvailLightClient lc = newAvailLightClient(fixtures[0].initial);
        LightClientStep memory step;

        step.blockNumber = fixtures[0].step.blockNumber;
        step.executionStateRoot = fixtures[0].step.executionStateRoot;
        step.headerRoot = fixtures[0].step.headerRoot;
        step.parentRoot = fixtures[0].step.parentRoot;

        lc.step(step);

        assertTrue(lc.head() == step.blockNumber);
        assertTrue(lc.finalizedHead() != step.blockNumber);
        assertTrue(lc.headerRoots(step.blockNumber) == step.headerRoot);
        assertTrue(lc.executionStateRoots(step.blockNumber) == step.executionStateRoot);

        LightClientFinalize memory finalize;

        finalize.blockNumber = fixtures[0].finalize.blockNumber;
        finalize.headerRoot = fixtures[0].finalize.headerRoot;
        finalize.authoritySetProof = AuthoritySetProof({
            authoritySetID: fixtures[0].finalize.authoritySetID,
            merkleProof: fixtures[0].finalize.merkleProof
        });
        lc.finalize(finalize);

        assertTrue(lc.finalizedHead() == finalize.blockNumber);

        LightClientRotate memory rotate;

        rotate.blockNumber = fixtures[0].rotate.blockNumber;
        rotate.eventListProof = EventListProof({
            encodedEventList: fixtures[0].rotate.encodedEventList,
            merkleProof: fixtures[0].rotate.encodedEventListProof
        });
        rotate.newAuthoritySetProof = AuthoritySetProof({
            authoritySetID: fixtures[0].rotate.newAuthoritySetID,
            merkleProof: fixtures[0].rotate.newAuthoritySetIDProof
        });

        lc.rotate(rotate);

        assertTrue(lc.authorityPubKeys(rotate.newAuthoritySetProof.authoritySetID, 0) == bytes32(0x0c7b217a62b4cf3dbaed046b3fd2dfef0591206b4fc1ad16ea6dcfb8c2614c55));
        assertTrue(lc.authorityPubKeys(rotate.newAuthoritySetProof.authoritySetID, 1) == bytes32(0x8d9b15ea8335270510135b7f7c5ef94e0df70e751d3c5f95fd1aa6d7766929b6));
        assertTrue(lc.authorityPubKeys(rotate.newAuthoritySetProof.authoritySetID, 2) == bytes32(0xe1288d95d48c12389b4398d2bf76998e9452c40e022bd63f9da529855d427b24));
        assertTrue(lc.authorityPubKeys(rotate.newAuthoritySetProof.authoritySetID, 3) == bytes32(0xcc6de644a35f4b205603fa125612df211d4f9d75e07c84d85cd35ea32a6b1ced));
        assertTrue(lc.authorityPubKeys(rotate.newAuthoritySetProof.authoritySetID, 4) == bytes32(0xe4c08a068e72a466e2f377e862b5b2ed473c4f0e58d7d265a123ad11fef2a797));
        assertTrue(lc.authorityPubKeys(rotate.newAuthoritySetProof.authoritySetID, 5) == bytes32(0x2ba7c00bfcc12b56a306c41ec44c411042d0b837a40d80fc652fa58ccfb78600));
        assertTrue(lc.authorityPubKeys(rotate.newAuthoritySetProof.authoritySetID, 6) == bytes32(0x079590df34cd1fa2f83cb1ef770b3e254abb00fa7dbfb2f7f21b383a7a726bb2));
        assertTrue(lc.authorityPubKeys(rotate.newAuthoritySetProof.authoritySetID, 7) == bytes32(0x335a446d556bd8b12d2e87b2c2b0a2b612f89c959ac60f955c334489c0363e43));
        assertTrue(lc.authorityPubKeys(rotate.newAuthoritySetProof.authoritySetID, 8) == bytes32(0xd4bb88f5cf51c64c98fddcf13839a48de35859804e4e3b6db227e9b157d832ec));
        assertTrue(lc.authorityPubKeys(rotate.newAuthoritySetProof.authoritySetID, 9) == bytes32(0x483e7490bc12a4e782224a513bbf581dfd85e89117b4e0f5663b77075e041097));
    }
}
