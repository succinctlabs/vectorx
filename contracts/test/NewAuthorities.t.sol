// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/NewAuthorities.sol";

contract NewAuthoritiesTest is Test {
    NewAuthorities public newAuthorities;

    function setUp() public {
        newAuthorities = new NewAuthorities();
    }

    function testDecodeEventsList() public {
        Authority[] memory expectedAuthorities = new Authority[](10);

        expectedAuthorities[0] = Authority(bytes32(0x0c7b217a62b4cf3dbaed046b3fd2dfef0591206b4fc1ad16ea6dcfb8c2614c55), 1);
        expectedAuthorities[1] = Authority(bytes32(0x8d9b15ea8335270510135b7f7c5ef94e0df70e751d3c5f95fd1aa6d7766929b6), 1);
        expectedAuthorities[2] = Authority(bytes32(0xe1288d95d48c12389b4398d2bf76998e9452c40e022bd63f9da529855d427b24), 1);
        expectedAuthorities[3] = Authority(bytes32(0xcc6de644a35f4b205603fa125612df211d4f9d75e07c84d85cd35ea32a6b1ced), 1);
        expectedAuthorities[4] = Authority(bytes32(0xe4c08a068e72a466e2f377e862b5b2ed473c4f0e58d7d265a123ad11fef2a797), 1);
        expectedAuthorities[5] = Authority(bytes32(0x2ba7c00bfcc12b56a306c41ec44c411042d0b837a40d80fc652fa58ccfb78600), 1);
        expectedAuthorities[6] = Authority(bytes32(0x079590df34cd1fa2f83cb1ef770b3e254abb00fa7dbfb2f7f21b383a7a726bb2), 1);
        expectedAuthorities[7] = Authority(bytes32(0x335a446d556bd8b12d2e87b2c2b0a2b612f89c959ac60f955c334489c0363e43), 1);
        expectedAuthorities[8] = Authority(bytes32(0xd4bb88f5cf51c64c98fddcf13839a48de35859804e4e3b6db227e9b157d832ec), 1);
        expectedAuthorities[9] = Authority(bytes32(0x483e7490bc12a4e782224a513bbf581dfd85e89117b4e0f5663b77075e041097), 1);

        bytes memory encodedEventList = hex"04011100280c7b217a62b4cf3dbaed046b3fd2dfef0591206b4fc1ad16ea6dcfb8c2614c5501000000000000008d9b15ea8335270510135b7f7c5ef94e0df70e751d3c5f95fd1aa6d7766929b60100000000000000e1288d95d48c12389b4398d2bf76998e9452c40e022bd63f9da529855d427b240100000000000000cc6de644a35f4b205603fa125612df211d4f9d75e07c84d85cd35ea32a6b1ced0100000000000000e4c08a068e72a466e2f377e862b5b2ed473c4f0e58d7d265a123ad11fef2a79701000000000000002ba7c00bfcc12b56a306c41ec44c411042d0b837a40d80fc652fa58ccfb786000100000000000000079590df34cd1fa2f83cb1ef770b3e254abb00fa7dbfb2f7f21b383a7a726bb20100000000000000335a446d556bd8b12d2e87b2c2b0a2b612f89c959ac60f955c334489c0363e430100000000000000d4bb88f5cf51c64c98fddcf13839a48de35859804e4e3b6db227e9b157d832ec0100000000000000483e7490bc12a4e782224a513bbf581dfd85e89117b4e0f5663b77075e041097010000000000000000";

        Authority[] memory decodedAuthorities = newAuthorities.decodeEventList(encodedEventList);

        for (uint i = 0; i < decodedAuthorities.length; i++) {
            assertEq(expectedAuthorities[i].eddsa_pub_key, decodedAuthorities[i].eddsa_pub_key, "Authority should match");
            assertEq(expectedAuthorities[i].weight, decodedAuthorities[i].weight, "Weight should match");
        }
    }

}
