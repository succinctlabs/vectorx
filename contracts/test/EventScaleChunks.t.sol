// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/EventScaleChunks.sol";
import { NUM_AUTHORITIES } from "../src/Constants.sol";

contract EventScaleChunksTest is Test {
    AvailEventScaleChunks decoder;

    function setUp() public {
        decoder = new AvailEventScaleChunks();
    }

    function testDecodeEventsListOne() public {
        bytes32[NUM_AUTHORITIES] memory expectedAuthorities;

        expectedAuthorities[0] = bytes32(0x0c7b217a62b4cf3dbaed046b3fd2dfef0591206b4fc1ad16ea6dcfb8c2614c55);
        expectedAuthorities[1] = bytes32(0x8d9b15ea8335270510135b7f7c5ef94e0df70e751d3c5f95fd1aa6d7766929b6);
        expectedAuthorities[2] = bytes32(0xe1288d95d48c12389b4398d2bf76998e9452c40e022bd63f9da529855d427b24);
        expectedAuthorities[3] = bytes32(0xcc6de644a35f4b205603fa125612df211d4f9d75e07c84d85cd35ea32a6b1ced);
        expectedAuthorities[4] = bytes32(0xe4c08a068e72a466e2f377e862b5b2ed473c4f0e58d7d265a123ad11fef2a797);
        expectedAuthorities[5] = bytes32(0x2ba7c00bfcc12b56a306c41ec44c411042d0b837a40d80fc652fa58ccfb78600);
        expectedAuthorities[6] = bytes32(0x079590df34cd1fa2f83cb1ef770b3e254abb00fa7dbfb2f7f21b383a7a726bb2);
        expectedAuthorities[7] = bytes32(0x335a446d556bd8b12d2e87b2c2b0a2b612f89c959ac60f955c334489c0363e43);
        expectedAuthorities[8] = bytes32(0xd4bb88f5cf51c64c98fddcf13839a48de35859804e4e3b6db227e9b157d832ec);
        expectedAuthorities[9] = bytes32(0x483e7490bc12a4e782224a513bbf581dfd85e89117b4e0f5663b77075e041097);

        bytes memory encodedEventList = hex"04011100280c7b217a62b4cf3dbaed046b3fd2dfef0591206b4fc1ad16ea6dcfb8c2614c5501000000000000008d9b15ea8335270510135b7f7c5ef94e0df70e751d3c5f95fd1aa6d7766929b60100000000000000e1288d95d48c12389b4398d2bf76998e9452c40e022bd63f9da529855d427b240100000000000000cc6de644a35f4b205603fa125612df211d4f9d75e07c84d85cd35ea32a6b1ced0100000000000000e4c08a068e72a466e2f377e862b5b2ed473c4f0e58d7d265a123ad11fef2a79701000000000000002ba7c00bfcc12b56a306c41ec44c411042d0b837a40d80fc652fa58ccfb786000100000000000000079590df34cd1fa2f83cb1ef770b3e254abb00fa7dbfb2f7f21b383a7a726bb20100000000000000335a446d556bd8b12d2e87b2c2b0a2b612f89c959ac60f955c334489c0363e430100000000000000d4bb88f5cf51c64c98fddcf13839a48de35859804e4e3b6db227e9b157d832ec0100000000000000483e7490bc12a4e782224a513bbf581dfd85e89117b4e0f5663b77075e041097010000000000000000";

        bytes32[NUM_AUTHORITIES] memory decodedAuthorities = decoder.decodeAuthoritySet(encodedEventList);

        for (uint i = 0; i < decodedAuthorities.length; i++) {
            assertEq(expectedAuthorities[i], decodedAuthorities[i], "Authority should match");
        }
    }

    function testDecodeEventsListMany() public {
        bytes32[NUM_AUTHORITIES] memory expectedAuthorities;

        expectedAuthorities[0] = bytes32(0x0c7b217a62b4cf3dbaed046b3fd2dfef0591206b4fc1ad16ea6dcfb8c2614c55);
        expectedAuthorities[1] = bytes32(0x8d9b15ea8335270510135b7f7c5ef94e0df70e751d3c5f95fd1aa6d7766929b6);
        expectedAuthorities[2] = bytes32(0xe1288d95d48c12389b4398d2bf76998e9452c40e022bd63f9da529855d427b24);
        expectedAuthorities[3] = bytes32(0xcc6de644a35f4b205603fa125612df211d4f9d75e07c84d85cd35ea32a6b1ced);
        expectedAuthorities[4] = bytes32(0xe4c08a068e72a466e2f377e862b5b2ed473c4f0e58d7d265a123ad11fef2a797);
        expectedAuthorities[5] = bytes32(0x2ba7c00bfcc12b56a306c41ec44c411042d0b837a40d80fc652fa58ccfb78600);
        expectedAuthorities[6] = bytes32(0x079590df34cd1fa2f83cb1ef770b3e254abb00fa7dbfb2f7f21b383a7a726bb2);
        expectedAuthorities[7] = bytes32(0x335a446d556bd8b12d2e87b2c2b0a2b612f89c959ac60f955c334489c0363e43);
        expectedAuthorities[8] = bytes32(0xd4bb88f5cf51c64c98fddcf13839a48de35859804e4e3b6db227e9b157d832ec);
        expectedAuthorities[9] = bytes32(0x483e7490bc12a4e782224a513bbf581dfd85e89117b4e0f5663b77075e041097);

        bytes memory encodedEventList = hex"240214020454565c44d9561b54219d44200551ab30df36bbca0cd777991868e09344c70f751b958da3cce7cc04026701178e7d642d2d1b8b513604a4ce65677bdad5df37463a583b2c0cd86f2d9ba097d5e3340c2e0c0f57f5ff111b07103f9fbab179b0300100020a0a54565c44d9561b54219d44200551ab30df36bbca0cd777991868e09344c70f7500021600696d2d6f6e6c696e653a6f66666c696e10870c000000020a0017020000c549f41bd5376aa607000000000000008e4efcb6c70314531600000000000000000206076d6f646c70792f747273727900000000000000000000000000000000000000008e4efcb6c70314531600000000000000000212068e4efcb6c7031453160000000000000000020b00880c00000000000000000000585f8f0900000000020000011100280c7b217a62b4cf3dbaed046b3fd2dfef0591206b4fc1ad16ea6dcfb8c2614c5501000000000000008d9b15ea8335270510135b7f7c5ef94e0df70e751d3c5f95fd1aa6d7766929b60100000000000000e1288d95d48c12389b4398d2bf76998e9452c40e022bd63f9da529855d427b240100000000000000cc6de644a35f4b205603fa125612df211d4f9d75e07c84d85cd35ea32a6b1ced0100000000000000e4c08a068e72a466e2f377e862b5b2ed473c4f0e58d7d265a123ad11fef2a79701000000000000002ba7c00bfcc12b56a306c41ec44c411042d0b837a40d80fc652fa58ccfb786000100000000000000079590df34cd1fa2f83cb1ef770b3e254abb00fa7dbfb2f7f21b383a7a726bb20100000000000000335a446d556bd8b12d2e87b2c2b0a2b612f89c959ac60f955c334489c0363e430100000000000000d4bb88f5cf51c64c98fddcf13839a48de35859804e4e3b6db227e9b157d832ec0100000000000000483e7490bc12a4e782224a513bbf581dfd85e89117b4e0f5663b77075e041097010000000000000000";

        bytes32[NUM_AUTHORITIES] memory decodedAuthorities = decoder.decodeAuthoritySet(encodedEventList);

        for (uint i = 0; i < decodedAuthorities.length; i++) {
            assertEq(expectedAuthorities[i], decodedAuthorities[i], "Authority should match");
        }
    }

}
