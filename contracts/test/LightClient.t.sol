pragma solidity 0.8.17;

import "forge-std/Vm.sol";
import "forge-std/console.sol";
import "forge-std/Test.sol";

import { LightClient,
         AuthoritySetIDProof,
         EventListProof,
         Header,
         Step as LCStep,
         Rotate as LCRotate } from "src/LightClient.sol";
import { NUM_AUTHORITIES } from "src/Constants.sol";
import { LightClientFixture } from "test/LightClientFixture.sol";
import { Strings } from "openzeppelin-contracts/utils/Strings.sol";

contract LightClientTest is Test, LightClientFixture {
    uint256 constant FIXTURE_BLOCK_START = 576727;
    uint256 constant FIXTURE_BLOCK_END = 576727;

    Initial fixtureInitial;
    Step fixtureStep;
    Rotate fixtureRotate;

    function setUp() public {
        // read all fixtures from entire directory
        string memory root = vm.projectRoot();

        string memory initialFilename = string.concat(root, "/test/LightClient/fixtures/initial.json");
        bytes memory initialParsed = vm.parseJson(vm.readFile(initialFilename));
        fixtureInitial = abi.decode(initialParsed, (Initial));

        string memory stepFilename = string.concat(root, "/test/LightClient/fixtures/step.json");
        bytes memory stepParsed = vm.parseJson(vm.readFile(stepFilename));
        fixtureStep = abi.decode(stepParsed, (Step));

        string memory rotateFilename = string.concat(root, "/test/LightClient/fixtures/rotate.json");
        bytes memory rotateParsed = vm.parseJson(vm.readFile(rotateFilename));
        fixtureRotate = abi.decode(rotateParsed, (Rotate));
    }

    function test_SetUp() public {
        assertTrue(fixtureInitial.blockNumber > 0);
        assertTrue(fixtureStep.blockNumbers.length > 0);
        assertTrue(fixtureRotate.newAuthoritySetID > 0);
    }

    function test_LightClientConstruction() public {
        LightClient lc = newLightClient(fixtureInitial);

        assertTrue(lc.START_CHECKPOINT_BLOCK_NUMBER() == fixtureInitial.blockNumber);
        assertTrue(lc.head() == fixtureInitial.blockNumber);
        assertTrue(lc.headerHashes(fixtureInitial.blockNumber) == fixtureInitial.startCheckpointHeaderHash);
        assertTrue(lc.stateRoots(fixtureInitial.blockNumber) == fixtureInitial.startCheckpointStateRoot);
        assertTrue(lc.dataRoots(fixtureInitial.blockNumber) == fixtureInitial.startCheckpointDataRoot);
        assertTrue(lc.activeAuthoritySetID() == fixtureInitial.authoritySetID);

        for (uint16 i = 0; i < NUM_AUTHORITIES; i++) {
            assertTrue(lc.authoritySets(fixtureInitial.authoritySetID, i) == fixtureInitial.authorityPubKeys[i]);
        }
    }

    function test_LightClientStep() public {
        LightClient lc = newLightClient(fixtureInitial);
        LCStep memory step;
        step.headers = new Header[](fixtureStep.blockNumbers.length);

        for (uint8 i = 0; i < fixtureStep.blockNumbers.length; i++) {
            step.headers[i] = Header({
                    blockNumber: fixtureStep.blockNumbers[i],
                    dataRoot: fixtureStep.dataRoots[i],
                    headerHash: fixtureStep.headerHashes[i],
                    stateRoot: fixtureStep.stateRoots[i]
                });
        }

        step.authoritySetIDProof.authoritySetID = fixtureStep.authoritySetID;
        step.authoritySetIDProof.merkleProof = fixtureStep.merkleProof;

        lc.step(step);

        assertTrue(lc.head() == fixtureStep.blockNumbers[fixtureStep.blockNumbers.length - 1]);
        for (uint8 i = 0; i < fixtureStep.blockNumbers.length; i++) {
            uint32 blockNumber = fixtureStep.blockNumbers[i];
            assertTrue(lc.dataRoots(blockNumber) == fixtureStep.dataRoots[i]);
            assertTrue(lc.headerHashes(blockNumber) == fixtureStep.headerHashes[i]);
            assertTrue(lc.stateRoots(blockNumber) == fixtureStep.stateRoots[i]);
        }
    }

    function test_LightClientStepRotate() public {
        LightClient lc = newLightClient(fixtureInitial);
        LCStep memory step;
        step.headers = new Header[](fixtureStep.blockNumbers.length);

        for (uint8 i = 0; i < fixtureStep.blockNumbers.length; i++) {
            step.headers[i] = Header({
                    blockNumber: fixtureStep.blockNumbers[i],
                    dataRoot: fixtureStep.dataRoots[i],
                    headerHash: fixtureStep.headerHashes[i],
                    stateRoot: fixtureStep.stateRoots[i]
                });
        }

        step.authoritySetIDProof.authoritySetID = fixtureStep.authoritySetID;
        step.authoritySetIDProof.merkleProof = fixtureStep.merkleProof;

        lc.step(step);

        assertTrue(lc.head() == fixtureStep.blockNumbers[fixtureStep.blockNumbers.length - 1]);
        for (uint8 i = 0; i < fixtureStep.blockNumbers.length; i++) {
            uint32 blockNumber = fixtureStep.blockNumbers[i];
            assertTrue(lc.dataRoots(blockNumber) == fixtureStep.dataRoots[i]);
            assertTrue(lc.headerHashes(blockNumber) == fixtureStep.headerHashes[i]);
            assertTrue(lc.stateRoots(blockNumber) == fixtureStep.stateRoots[i]);
        }

        LCRotate memory rotate;

        rotate.eventListProof = EventListProof({
            encodedEventList: fixtureRotate.encodedEventList,
            merkleProof: fixtureRotate.encodedEventListProof
        });
        rotate.newAuthoritySetIDProof = AuthoritySetIDProof({
            authoritySetID: fixtureRotate.newAuthoritySetID,
            merkleProof: fixtureRotate.newAuthoritySetIDProof
        });
        rotate.step.headers = new Header[](fixtureRotate.step.blockNumbers.length);

        for (uint8 i = 0; i < fixtureRotate.step.blockNumbers.length; i++) {
            rotate.step.headers[i] = Header({
                    blockNumber: fixtureRotate.step.blockNumbers[i],
                    dataRoot: fixtureRotate.step.dataRoots[i],
                    headerHash: fixtureRotate.step.headerHashes[i],
                    stateRoot: fixtureRotate.step.stateRoots[i]
                });
        }

        rotate.step.authoritySetIDProof.authoritySetID = fixtureRotate.step.authoritySetID;
        rotate.step.authoritySetIDProof.merkleProof = fixtureRotate.step.merkleProof;

        lc.rotate(rotate);

        assertTrue(lc.head() == fixtureRotate.step.blockNumbers[fixtureRotate.step.blockNumbers.length - 1]);
        for (uint8 i = 0; i < fixtureRotate.step.blockNumbers.length; i++) {
            uint32 blockNumber = fixtureRotate.step.blockNumbers[i];
            assertTrue(lc.dataRoots(blockNumber) == fixtureRotate.step.dataRoots[i]);
            assertTrue(lc.headerHashes(blockNumber) == fixtureRotate.step.headerHashes[i]);
            assertTrue(lc.stateRoots(blockNumber) == fixtureRotate.step.stateRoots[i]);
        }

        assertTrue(lc.authoritySets(rotate.newAuthoritySetIDProof.authoritySetID, 0) == bytes32(0x0c7b217a62b4cf3dbaed046b3fd2dfef0591206b4fc1ad16ea6dcfb8c2614c55));
        assertTrue(lc.authoritySets(rotate.newAuthoritySetIDProof.authoritySetID, 1) == bytes32(0x8d9b15ea8335270510135b7f7c5ef94e0df70e751d3c5f95fd1aa6d7766929b6));
        assertTrue(lc.authoritySets(rotate.newAuthoritySetIDProof.authoritySetID, 2) == bytes32(0xe1288d95d48c12389b4398d2bf76998e9452c40e022bd63f9da529855d427b24));
        assertTrue(lc.authoritySets(rotate.newAuthoritySetIDProof.authoritySetID, 3) == bytes32(0xcc6de644a35f4b205603fa125612df211d4f9d75e07c84d85cd35ea32a6b1ced));
        assertTrue(lc.authoritySets(rotate.newAuthoritySetIDProof.authoritySetID, 4) == bytes32(0xe4c08a068e72a466e2f377e862b5b2ed473c4f0e58d7d265a123ad11fef2a797));
        assertTrue(lc.authoritySets(rotate.newAuthoritySetIDProof.authoritySetID, 5) == bytes32(0x2ba7c00bfcc12b56a306c41ec44c411042d0b837a40d80fc652fa58ccfb78600));
        assertTrue(lc.authoritySets(rotate.newAuthoritySetIDProof.authoritySetID, 6) == bytes32(0x079590df34cd1fa2f83cb1ef770b3e254abb00fa7dbfb2f7f21b383a7a726bb2));
        assertTrue(lc.authoritySets(rotate.newAuthoritySetIDProof.authoritySetID, 7) == bytes32(0x335a446d556bd8b12d2e87b2c2b0a2b612f89c959ac60f955c334489c0363e43));
        assertTrue(lc.authoritySets(rotate.newAuthoritySetIDProof.authoritySetID, 8) == bytes32(0xd4bb88f5cf51c64c98fddcf13839a48de35859804e4e3b6db227e9b157d832ec));
        assertTrue(lc.authoritySets(rotate.newAuthoritySetIDProof.authoritySetID, 9) == bytes32(0x483e7490bc12a4e782224a513bbf581dfd85e89117b4e0f5663b77075e041097));
    }

    /*
    function test_LightClientStep_badParentRoot() public {
        string memory path = string.concat(
            vm.projectRoot(), "/test/LightClient/fixtures/block576727_bad1.json"
        );
        bytes memory parsed = vm.parseJson(vm.readFile(path));
        Fixture memory fixture = abi.decode(parsed, (Fixture));

        LightClient lc = newLightClient(fixture.initial);
        LCStep memory step;
        
        step.blockNumber = fixture.step.blockNumber;
        step.executionStateRoot = fixture.step.executionStateRoot;
        step.headerRoot = fixture.step.headerRoot;
        step.parentRoot = fixture.step.parentRoot;

        vm.expectRevert();
        lc.step(step);
    }

    function test_LightClientStep_badBlockNumber() public {
        string memory path = string.concat(
            vm.projectRoot(), "/test/LightClient/fixtures/block576727_bad2.json"
        );
        bytes memory parsed = vm.parseJson(vm.readFile(path));
        Fixture memory fixture = abi.decode(parsed, (Fixture));

        LightClient lc = newLightClient(fixture.initial);
        LCStep memory step;
        
        step.blockNumber = fixture.step.blockNumber;
        step.executionStateRoot = fixture.step.executionStateRoot;
        step.headerRoot = fixture.step.headerRoot;
        step.parentRoot = fixture.step.parentRoot;

        vm.expectRevert();
        lc.step(step);
    }
    */
}
