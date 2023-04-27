pragma solidity 0.8.17;

import "forge-std/Vm.sol";
import "forge-std/console.sol";
import "forge-std/Test.sol";

import {AvailLightClient, LightClientStep, NUM_AUTHORITIES} from "src/AvailLightClient.sol";
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

        assertTrue(lc.GENESIS_SLOT() == initial.genesisSlot);
        assertTrue(lc.START_CHECKPOINT_SLOT() == initial.startCheckpointSlot);
        assertTrue(lc.START_CHECKPOINT_BLOCK_NUMBER() == initial.startCheckpointBlockNumber);
        assertTrue(lc.head() == initial.startCheckpointBlockNumber);
        assertTrue(lc.finalizedHead() == initial.startCheckpointBlockNumber);
        assertTrue(lc.headerRoots(initial.startCheckpointBlockNumber) == initial.startCheckpointHeaderRoot);
        assertTrue(lc.executionStateRoots(initial.startCheckpointBlockNumber) == initial.startCheckpointExecutionRoot);

        uint64 epochIndex = lc.epochIndex();
        assertTrue(epochIndex == 3207);

        for (uint16 i = 0; i < NUM_AUTHORITIES; i++) {
            assertTrue(lc.authorityPuKeys(epochIndex, i) == initial.authorityPubKeys[i]);
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
}