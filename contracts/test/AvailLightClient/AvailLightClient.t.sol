pragma solidity 0.8.17;

import "forge-std/Vm.sol";
import "forge-std/console.sol";
import "forge-std/Test.sol";

import {Authority, AvailLightClient} from "src/AvailLightClient.sol";

contract AvailLightClientTest is Test {
    uint256 constant FIXTURE_BLOCK_START = 576727;
    uint256 constant FIXTURE_BLOCK_END = 576727;

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

    /*
    function setUp() public {
        Authority[10] memory authoritySet;
        authoritySet[0] = Authority("0x0c7b217a62b4cf3dbaed046b3fd2dfef0591206b4fc1ad16ea6dcfb8c2614c55", 1);
        authoritySet[1] = Authority("0x8d9b15ea8335270510135b7f7c5ef94e0df70e751d3c5f95fd1aa6d7766929b6", 1);
        authoritySet[2] = Authority("0xe1288d95d48c12389b4398d2bf76998e9452c40e022bd63f9da529855d427b24", 1);
        authoritySet[3] = Authority("0xcc6de644a35f4b205603fa125612df211d4f9d75e07c84d85cd35ea32a6b1ced", 1);
        authoritySet[4] = Authority("0xe4c08a068e72a466e2f377e862b5b2ed473c4f0e58d7d265a123ad11fef2a797", 1);
        authoritySet[5] = Authority("0x2ba7c00bfcc12b56a306c41ec44c411042d0b837a40d80fc652fa58ccfb78600", 1);
        authoritySet[6] = Authority("0x079590df34cd1fa2f83cb1ef770b3e254abb00fa7dbfb2f7f21b383a7a726bb2", 1);
        authoritySet[7] = Authority("0x335a446d556bd8b12d2e87b2c2b0a2b612f89c959ac60f955c334489c0363e43", 1);
        authoritySet[8] = Authority("0xd4bb88f5cf51c64c98fddcf13839a48de35859804e4e3b6db227e9b157d832ec", 1);
        authoritySet[9] = Authority("0x483e7490bc12a4e782224a513bbf581dfd85e89117b4e0f5663b77075e041097", 1);

        // Initialize the light client to block# 576727 of the Avail testnet (https://testnet.avail.tools/#/explorer/query/576727)
        lc = new AvailLightClient(83483474, authoritySet, 84060913, 576727, "0x91257bc931df2d9a91f32dae6ca607ae9e411b38ed8738738eafe7bb816d1464", "0xee4ad636031fc1c7df369a90af680d54543c0de95bf40ab723289846715b95ad");
    }

    function test_SetUp() public {
        assertTrue(lc.GENESIS_SLOT == 83483474);
        assertTrue(lc.START_CHECKPOINT_SLOT == 84060913);
        assertTrue(lc.START_CHECKPOINT_BLOCK_NUMBER == 576727);
        assertTrue(lc.head == 576727);
        assertTrue(lc.headRoot = "0x91257bc931df2d9a91f32dae6ca607ae9e411b38ed8738738eafe7bb816d1464");
        assertTrue(lc.finalizedHead == 576727);
        assertTrue(lc.finalizedHeadRoot = "0x91257bc931df2d9a91f32dae6ca607ae9e411b38ed8738738eafe7bb816d1464");
        assertTrue(lc.headerRoots[576727] == "0x91257bc931df2d9a91f32dae6ca607ae9e411b38ed8738738eafe7bb816d1464");
        assertTrue(lc.executionStateRoots[576727] == "0xee4ad636031fc1c7df369a90af680d54543c0de95bf40ab723289846715b95ad");

        Authority[10] memory authoritySet = lc.authorities[lc.epochIndex];
        assertTrue(authoritySet[0].eddsa_pub_key == "0x0c7b217a62b4cf3dbaed046b3fd2dfef0591206b4fc1ad16ea6dcfb8c2614c55");
        assertTrue(authoritySet[0].weight == 1);
        assertTrue(authoritySet[1].eddsa_pub_key == "0x8d9b15ea8335270510135b7f7c5ef94e0df70e751d3c5f95fd1aa6d7766929b6");
        assertTrue(authoritySet[1].weight == 1);
        assertTrue(authoritySet[2].eddsa_pub_key == "0xe1288d95d48c12389b4398d2bf76998e9452c40e022bd63f9da529855d427b24");
        assertTrue(authoritySet[2].weight == 1);
        assertTrue(authoritySet[3].eddsa_pub_key == "0xcc6de644a35f4b205603fa125612df211d4f9d75e07c84d85cd35ea32a6b1ced");
        assertTrue(authoritySet[3].weight == 1);
        assertTrue(authoritySet[4].eddsa_pub_key == "0xe4c08a068e72a466e2f377e862b5b2ed473c4f0e58d7d265a123ad11fef2a797");
        assertTrue(authoritySet[4].weight == 1);
        assertTrue(authoritySet[5].eddsa_pub_key == "0x2ba7c00bfcc12b56a306c41ec44c411042d0b837a40d80fc652fa58ccfb78600");
        assertTrue(authoritySet[5].weight == 1);
        assertTrue(authoritySet[6].eddsa_pub_key == "0x079590df34cd1fa2f83cb1ef770b3e254abb00fa7dbfb2f7f21b383a7a726bb2");
        assertTrue(authoritySet[6].weight == 1);
        assertTrue(authoritySet[7].eddsa_pub_key == "0x335a446d556bd8b12d2e87b2c2b0a2b612f89c959ac60f955c334489c0363e43");
        assertTrue(authoritySet[7].weight == 1);
        assertTrue(authoritySet[8].eddsa_pub_key == "0xd4bb88f5cf51c64c98fddcf13839a48de35859804e4e3b6db227e9b157d832ec");
        assertTrue(authoritySet[8].weight == 1);
        assertTrue(authoritySet[9].eddsa_pub_key == "0x483e7490bc12a4e782224a513bbf581dfd85e89117b4e0f5663b77075e041097");
        assertTrue(authoritySet[9].weight == 1);        
    }
    */
}