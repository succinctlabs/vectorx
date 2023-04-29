pragma solidity 0.8.17;

import { ByteSlice, Bytes } from "solidity-merkle-trees/src/trie/Bytes.sol";
import { ScaleCodec } from "solidity-merkle-trees/src/trie/substrate/ScaleCodec.sol";
import { NUM_AUTHORITIES } from "src/AvailLightClient.sol";

contract AvailEventScaleChunks {
    enum chunkType{ CONSTANT_SIZE, COMPACT, SEQUENCE }

    struct Chunk {
        chunkType chunkType;
        uint32 size;
        Chunk[] sequenceChunks;
    }

    mapping(uint8 => mapping(uint8 => Chunk[])) eventChunks;

    constructor() {
        eventChunks[0][0].push();
        eventChunks[0][0][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[0][0][0].size = 14;
        eventChunks[0][1].push();
        eventChunks[0][1][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[0][1][0].size = 15;
        eventChunks[0][3].push();
        eventChunks[0][3][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[0][3][0].size = 32;
        eventChunks[0][4].push();
        eventChunks[0][4][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[0][4][0].size = 32;
        eventChunks[0][5].push();
        eventChunks[0][5][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[0][5][0].size = 64;
        eventChunks[1][0].push();
        eventChunks[1][0][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[1][0][0].size = 9;
        eventChunks[1][3].push();
        eventChunks[1][3][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[1][3][0].size = 6;
        eventChunks[5][0].push();
        eventChunks[5][0][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[5][0][0].size = 36;
        eventChunks[5][1].push();
        eventChunks[5][1][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[5][1][0].size = 4;
        eventChunks[5][2].push();
        eventChunks[5][2][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[5][2][0].size = 36;
        eventChunks[6][0].push();
        eventChunks[6][0][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[6][0][0].size = 48;
        eventChunks[6][1].push();
        eventChunks[6][1][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[6][1][0].size = 48;
        eventChunks[6][2].push();
        eventChunks[6][2][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[6][2][0].size = 80;
        eventChunks[6][3].push();
        eventChunks[6][3][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[6][3][0].size = 64;
        eventChunks[6][4].push();
        eventChunks[6][4][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[6][4][0].size = 48;
        eventChunks[6][5].push();
        eventChunks[6][5][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[6][5][0].size = 48;
        eventChunks[6][6].push();
        eventChunks[6][6][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[6][6][0].size = 81;
        eventChunks[6][7].push();
        eventChunks[6][7][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[6][7][0].size = 48;
        eventChunks[6][8].push();
        eventChunks[6][8][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[6][8][0].size = 48;
        eventChunks[6][9].push();
        eventChunks[6][9][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[6][9][0].size = 48;
        eventChunks[9][0].push();
        eventChunks[9][0][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[9][0][0].size = 2;
        eventChunks[9][1].push();
        eventChunks[9][1][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[9][1][0].size = 2;
        eventChunks[9][2].push();
        eventChunks[9][2][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[9][2][0].size = 48;
        eventChunks[9][3].push();
        eventChunks[9][3][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[9][3][0].size = 48;
        eventChunks[9][4].push();
        eventChunks[9][4][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[9][4][0].size = 4;
        eventChunks[9][5].push();
        eventChunks[9][5][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[9][5][0].size = 4;
        eventChunks[10][0].push();
        eventChunks[10][0][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[10][0][0].size = 36;
        eventChunks[10][1].push();
        eventChunks[10][1][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[10][1][0].size = 48;
        eventChunks[10][2].push();
        eventChunks[10][2][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[10][2][0].size = 48;
        eventChunks[10][3].push();
        eventChunks[10][3][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[10][3][0].size = 4;
        eventChunks[10][5].push();
        eventChunks[10][5][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[10][5][0].size = 48;
        eventChunks[10][6].push();
        eventChunks[10][6][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[10][6][0].size = 48;
        eventChunks[10][7].push();
        eventChunks[10][7][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[10][7][0].size = 48;
        eventChunks[10][8].push();
        eventChunks[10][8][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[10][8][0].size = 64;
        eventChunks[10][10].push();
        eventChunks[10][10][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[10][10][0].size = 32;
        eventChunks[10][11].push();
        eventChunks[10][11][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[10][11][0].size = 36;
        eventChunks[11][0].push();
        eventChunks[11][0][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[11][0][0].size = 4;
        eventChunks[12][0].push();
        eventChunks[12][0][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[12][0][0].size = 20;
        eventChunks[12][1].push();
        eventChunks[12][1][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[12][1][0].size = 20;
        eventChunks[12][1].push();
        eventChunks[12][1][1].chunkType = chunkType.SEQUENCE;
        eventChunks[12][1][1].sequenceChunks.push();
        eventChunks[12][1][1].sequenceChunks[0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[12][1][1].sequenceChunks[0].size = 32;
        eventChunks[12][3].push();
        eventChunks[12][3][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[12][3][0].size = 5;
        eventChunks[12][4].push();
        eventChunks[12][4][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[12][4][0].size = 4;
        eventChunks[12][5].push();
        eventChunks[12][5][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[12][5][0].size = 4;
        eventChunks[12][6].push();
        eventChunks[12][6][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[12][6][0].size = 4;
        eventChunks[12][7].push();
        eventChunks[12][7][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[12][7][0].size = 10;
        eventChunks[12][8].push();
        eventChunks[12][8][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[12][8][0].size = 64;
        eventChunks[12][9].push();
        eventChunks[12][9][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[12][9][0].size = 32;
        eventChunks[12][10].push();
        eventChunks[12][10][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[12][10][0].size = 68;
        eventChunks[12][11].push();
        eventChunks[12][11][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[12][11][0].size = 80;
        eventChunks[12][12].push();
        eventChunks[12][12][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[12][12][0].size = 80;
        eventChunks[12][13].push();
        eventChunks[12][13][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[12][13][0].size = 36;
        eventChunks[12][14].push();
        eventChunks[12][14][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[12][14][0].size = 36;
        eventChunks[12][15].push();
        eventChunks[12][15][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[12][15][0].size = 112;
        eventChunks[12][16].push();
        eventChunks[12][16][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[12][16][0].size = 32;
        eventChunks[13][0].push();
        eventChunks[13][0][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[13][0][0].size = 72;
        eventChunks[13][1].push();
        eventChunks[13][1][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[13][1][0].size = 73;
        eventChunks[13][2].push();
        eventChunks[13][2][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[13][2][0].size = 32;
        eventChunks[13][3].push();
        eventChunks[13][3][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[13][3][0].size = 32;
        eventChunks[13][4].push();
        eventChunks[13][4][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[13][4][0].size = 38;
        eventChunks[13][5].push();
        eventChunks[13][5][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[13][5][0].size = 38;
        eventChunks[13][6].push();
        eventChunks[13][6][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[13][6][0].size = 40;
        eventChunks[14][0].push();
        eventChunks[14][0][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[14][0][0].size = 72;
        eventChunks[14][1].push();
        eventChunks[14][1][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[14][1][0].size = 73;
        eventChunks[14][2].push();
        eventChunks[14][2][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[14][2][0].size = 32;
        eventChunks[14][3].push();
        eventChunks[14][3][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[14][3][0].size = 32;
        eventChunks[14][4].push();
        eventChunks[14][4][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[14][4][0].size = 38;
        eventChunks[14][5].push();
        eventChunks[14][5][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[14][5][0].size = 38;
        eventChunks[14][6].push();
        eventChunks[14][6][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[14][6][0].size = 40;
        eventChunks[15][0].push();
        eventChunks[15][0][0].chunkType = chunkType.SEQUENCE;
        eventChunks[15][0][0].sequenceChunks.push();
        eventChunks[15][0][0].sequenceChunks[0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[15][0][0].sequenceChunks[0].size = 48;
        eventChunks[15][3].push();
        eventChunks[15][3][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[15][3][0].size = 32;
        eventChunks[15][4].push();
        eventChunks[15][4][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[15][4][0].size = 32;
        eventChunks[15][5].push();
        eventChunks[15][5][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[15][5][0].size = 48;
        eventChunks[15][6].push();
        eventChunks[15][6][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[15][6][0].size = 48;
        eventChunks[17][0].push();
        eventChunks[17][0][0].chunkType = chunkType.SEQUENCE;
        eventChunks[17][0][0].sequenceChunks.push();
        eventChunks[17][0][0].sequenceChunks[0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[17][0][0].sequenceChunks[0].size = 40;
        eventChunks[18][0].push();
        eventChunks[18][0][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[18][0][0].size = 4;
        eventChunks[18][1].push();
        eventChunks[18][1][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[18][1][0].size = 16;
        eventChunks[18][2].push();
        eventChunks[18][2][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[18][2][0].size = 52;
        eventChunks[18][3].push();
        eventChunks[18][3][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[18][3][0].size = 20;
        eventChunks[18][4].push();
        eventChunks[18][4][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[18][4][0].size = 16;
        eventChunks[18][5].push();
        eventChunks[18][5][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[18][5][0].size = 16;
        eventChunks[18][6].push();
        eventChunks[18][6][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[18][6][0].size = 16;
        eventChunks[19][0].push();
        eventChunks[19][0][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[19][0][0].size = 6;
        eventChunks[19][1].push();
        eventChunks[19][1][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[19][1][0].size = 32;
        eventChunks[19][2].push();
        eventChunks[19][2][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[19][2][0].size = 6;
        eventChunks[20][0].push();
        eventChunks[20][0][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[20][0][0].size = 32;
        eventChunks[20][2].push();
        eventChunks[20][2][0].chunkType = chunkType.SEQUENCE;
        eventChunks[20][2][0].sequenceChunks.push();
        eventChunks[20][2][0].sequenceChunks[0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[20][2][0].sequenceChunks[0].size = 32;
        eventChunks[20][2][0].sequenceChunks.push();
        eventChunks[20][2][0].sequenceChunks[1].chunkType = chunkType.COMPACT;
        eventChunks[20][2][0].sequenceChunks.push();
        eventChunks[20][2][0].sequenceChunks[2].chunkType = chunkType.COMPACT;
        eventChunks[20][2][0].sequenceChunks.push();
        eventChunks[20][2][0].sequenceChunks[3].chunkType = chunkType.SEQUENCE;
        eventChunks[20][2][0].sequenceChunks[3].sequenceChunks.push();
        eventChunks[20][2][0].sequenceChunks[3].sequenceChunks[0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[20][2][0].sequenceChunks[3].sequenceChunks[0].size = 32;
        eventChunks[20][2][0].sequenceChunks[3].sequenceChunks.push();
        eventChunks[20][2][0].sequenceChunks[3].sequenceChunks[1].chunkType = chunkType.COMPACT;
        eventChunks[22][0].push();
        eventChunks[22][0][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[22][0][0].size = 16;
        eventChunks[22][0].push();
        eventChunks[22][0][1].chunkType = chunkType.SEQUENCE;
        eventChunks[22][0][1].sequenceChunks.push();
        eventChunks[22][0][1].sequenceChunks[0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[22][0][1].sequenceChunks[0].size = 1;
        eventChunks[24][0].push();
        eventChunks[24][0][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[24][0][0].size = 8;
        eventChunks[24][1].push();
        eventChunks[24][1][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[24][1][0].size = 8;
        eventChunks[24][2].push();
        eventChunks[24][2][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[24][2][0].size = 9;
        eventChunks[24][2].push();
        eventChunks[24][2][1].chunkType = chunkType.SEQUENCE;
        eventChunks[24][2][1].sequenceChunks.push();
        eventChunks[24][2][1].sequenceChunks[0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[24][2][1].sequenceChunks[0].size = 1;
        eventChunks[24][2].push();
        eventChunks[24][2][2].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[24][2][2].size = 6;
        eventChunks[25][0].push();
        eventChunks[25][0][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[25][0][0].size = 4;
        eventChunks[25][1].push();
        eventChunks[25][1][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[25][1][0].size = 20;
        eventChunks[25][2].push();
        eventChunks[25][2][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[25][2][0].size = 4;
        eventChunks[25][3].push();
        eventChunks[25][3][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[25][3][0].size = 36;
        eventChunks[25][4].push();
        eventChunks[25][4][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[25][4][0].size = 52;
        eventChunks[25][5].push();
        eventChunks[25][5][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[25][5][0].size = 4;
        eventChunks[25][6].push();
        eventChunks[25][6][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[25][6][0].size = 4;
        eventChunks[26][0].push();
        eventChunks[26][0][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[26][0][0].size = 32;
        eventChunks[26][1].push();
        eventChunks[26][1][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[26][1][0].size = 32;
        eventChunks[26][2].push();
        eventChunks[26][2][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[26][2][0].size = 80;
        eventChunks[26][3].push();
        eventChunks[26][3][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[26][3][0].size = 32;
        eventChunks[26][4].push();
        eventChunks[26][4][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[26][4][0].size = 80;
        eventChunks[28][0].push();
        eventChunks[28][0][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[28][0][0].size = 48;
        eventChunks[29][0].push();
        eventChunks[29][0][0].chunkType = chunkType.SEQUENCE;
        eventChunks[29][0][0].sequenceChunks.push();
        eventChunks[29][0][0].sequenceChunks[0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[29][0][0].sequenceChunks[0].size = 1;
        eventChunks[29][0].push();
        eventChunks[29][0][1].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[29][0][1].size = 32;
        eventChunks[29][0].push();
        eventChunks[29][0][2].chunkType = chunkType.COMPACT;
        eventChunks[29][1].push();
        eventChunks[29][1][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[29][1][0].size = 32;
        eventChunks[29][1].push();
        eventChunks[29][1][1].chunkType = chunkType.SEQUENCE;
        eventChunks[29][1][1].sequenceChunks.push();
        eventChunks[29][1][1].sequenceChunks[0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[29][1][1].sequenceChunks[0].size = 1;
        eventChunks[29][2].push();
        eventChunks[29][2][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[29][2][0].size = 8;
        eventChunks[30][0].push();
        eventChunks[30][0][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[30][0][0].size = 40;
        eventChunks[30][1].push();
        eventChunks[30][1][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[30][1][0].size = 32;
        eventChunks[31][0].push();
        eventChunks[31][0][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[31][0][0].size = 76;
        eventChunks[31][0].push();
        eventChunks[31][0][1].chunkType = chunkType.SEQUENCE;
        eventChunks[31][0][1].sequenceChunks.push();
        eventChunks[31][0][1].sequenceChunks[0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[31][0][1].sequenceChunks[0].size = 1;
        eventChunks[31][1].push();
        eventChunks[31][1][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[31][1][0].size = 68;
        eventChunks[31][1].push();
        eventChunks[31][1][1].chunkType = chunkType.SEQUENCE;
        eventChunks[31][1][1].sequenceChunks.push();
        eventChunks[31][1][1].sequenceChunks[0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[31][1][1].sequenceChunks[0].size = 1;
        eventChunks[31][2].push();
        eventChunks[31][2][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[31][2][0].size = 64;
        eventChunks[31][2].push();
        eventChunks[31][2][1].chunkType = chunkType.SEQUENCE;
        eventChunks[31][2][1].sequenceChunks.push();
        eventChunks[31][2][1].sequenceChunks[0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[31][2][1].sequenceChunks[0].size = 1;
        eventChunks[31][3].push();
        eventChunks[31][3][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[31][3][0].size = 52;
        eventChunks[32][0].push();
        eventChunks[32][0][0].chunkType = chunkType.CONSTANT_SIZE;
        eventChunks[32][0][0].size = 72;
    }


    function decodeAuthoritySet(bytes memory encodedEventList) external returns (bytes32[] memory) {
        ByteSlice memory encodedEventsListSlice = ByteSlice(encodedEventList, 0);

        // First get the length of the encoded_events_list
        uint256 num_events = ScaleCodec.decodeUintCompact(encodedEventsListSlice);

        bytes32[] memory authorities = new bytes32[](NUM_AUTHORITIES);

        uint8 phase;
        uint8 palletIndex;
        uint8 eventIndex;

        // Parse the scale encoded events
        for (uint256 i = 0; i < num_events; i++) {
            // First element is the Phase enum value (0 - ApplyExtrinsic, 1 - Finalization, 2 - Initialization)
            phase = Bytes.readByte(encodedEventsListSlice);

            // Second element is the pallet_index
            palletIndex = Bytes.readByte(encodedEventsListSlice);

            // Third element is the event_index
            eventIndex = Bytes.readByte(encodedEventsListSlice);

            // Decode the actual event
            if (phase == 1 && palletIndex == 17 && eventIndex == 0) {
                // This is the NewAuthorities event

                // The next element is the length of the encoded new authorities list
                uint256 numAuthorities = ScaleCodec.decodeUintCompact(encodedEventsListSlice);

                // Parse the scale encoded authorities
                for (uint256 j = 0; j < numAuthorities; j++) {
                    // First 32 bytes is the eddsa pub key
                    authorities[j] = Bytes.toBytes32(Bytes.read(encodedEventsListSlice, 32));
                    // Next 8 bytes is the weight.  We can ignore that.
                    Bytes.read(encodedEventsListSlice, 8);
                }
            } else {
                for (uint256 chunkIdx = 0; chunkIdx < eventChunks[palletIndex][eventIndex].length; chunkIdx++) {
                    jumpOverChunk(eventChunks[palletIndex][eventIndex][chunkIdx], encodedEventsListSlice);
                }
            }

            // There is a 0 value byte at the end of each event
            require(Bytes.readByte(encodedEventsListSlice) == 0, "last byte of event is not 0");
        }

        require(encodedEventsListSlice.offset == encodedEventList.length, "Did not parse all of the encoded events bytes");

        return authorities;
    }

    function jumpOverChunk(Chunk memory chunk, ByteSlice memory encodedEventsListSlice) internal {
        if (chunk.chunkType == chunkType.CONSTANT_SIZE) {
            Bytes.read(encodedEventsListSlice, chunk.size);
        } else if (chunk.chunkType == chunkType.COMPACT) {
            ScaleCodec.decodeUintCompact(encodedEventsListSlice);
        } else if (chunk.chunkType == chunkType.SEQUENCE) {
            uint256 numChunks = ScaleCodec.decodeUintCompact(encodedEventsListSlice);
            for (uint256 i = 0; i < numChunks; i++) {
                jumpOverChunk(chunk.sequenceChunks[i], encodedEventsListSlice);
            }
        } else {
            revert("Unknown chunk type");
        }
    }
}
