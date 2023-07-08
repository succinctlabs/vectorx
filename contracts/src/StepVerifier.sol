
// SPDX-License-Identifier: AML
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

// 2019 OKIMS

pragma solidity ^0.8.0;

library Pairing {

    uint256 constant PRIME_Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    struct G1Point {
        uint256 X;
        uint256 Y;
    }

    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint256[2] X;
        uint256[2] Y;
    }

    /*
     * @return The negation of p, i.e. p.plus(p.negate()) should be zero.
     */
    function negate(G1Point memory p) internal pure returns (G1Point memory) {

        // The prime q in the base field F_q for G1
        if (p.X == 0 && p.Y == 0) {
            return G1Point(0, 0);
        } else {
            return G1Point(p.X, PRIME_Q - (p.Y % PRIME_Q));
        }
    }

    /*
     * @return The sum of two points of G1
     */
    function plus(
        G1Point memory p1,
        G1Point memory p2
    ) internal view returns (G1Point memory r) {

        uint256[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;

        // solium-disable-next-line security/no-inline-assembly
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }

        require(success,"pairing-add-failed");
    }


    /*
     * Same as plus but accepts raw input instead of struct
     * @return The sum of two points of G1, one is represented as array
     */
    function plus_raw(uint256[4] memory input, G1Point memory r) internal view {
        bool success;

        // solium-disable-next-line security/no-inline-assembly
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 {invalid()}
        }

        require(success, "pairing-add-failed");
    }

    /*
     * @return The product of a point on G1 and a scalar, i.e.
     *         p == p.scalar_mul(1) and p.plus(p) == p.scalar_mul(2) for all
     *         points p.
     */
    function scalar_mul(G1Point memory p, uint256 s) internal view returns (G1Point memory r) {

        uint256[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require (success,"pairing-mul-failed");
    }


    /*
     * Same as scalar_mul but accepts raw input instead of struct,
     * Which avoid extra allocation. provided input can be allocated outside and re-used multiple times
     */
    function scalar_mul_raw(uint256[3] memory input, G1Point memory r) internal view {
        bool success;

        // solium-disable-next-line security/no-inline-assembly
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 {invalid()}
        }
        require(success, "pairing-mul-failed");
    }

    /* @return The result of computing the pairing check
     *         e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
     *         For example,
     *         pairing([P1(), P1().negate()], [P2(), P2()]) should return true.
     */
    function pairing(
        G1Point memory a1,
        G2Point memory a2,
        G1Point memory b1,
        G2Point memory b2,
        G1Point memory c1,
        G2Point memory c2,
        G1Point memory d1,
        G2Point memory d2
    ) internal view returns (bool) {

        G1Point[4] memory p1 = [a1, b1, c1, d1];
        G2Point[4] memory p2 = [a2, b2, c2, d2];
        uint256 inputSize = 24;
        uint256[] memory input = new uint256[](inputSize);

        for (uint256 i = 0; i < 4; i++) {
            uint256 j = i * 6;
            input[j + 0] = p1[i].X;
            input[j + 1] = p1[i].Y;
            input[j + 2] = p2[i].X[0];
            input[j + 3] = p2[i].X[1];
            input[j + 4] = p2[i].Y[0];
            input[j + 5] = p2[i].Y[1];
        }

        uint256[1] memory out;
        bool success;

        // solium-disable-next-line security/no-inline-assembly
        assembly {
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }

        require(success,"pairing-opcode-failed");

        return out[0] != 0;
    }
}

contract StepVerifier {

    using Pairing for *;

    uint256 constant SNARK_SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 constant PRIME_Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    struct VerifyingKey {
        Pairing.G1Point alfa1;
        Pairing.G2Point beta2;
        Pairing.G2Point gamma2;
        Pairing.G2Point delta2;
        // []G1Point IC (K in gnark) appears directly in verifyProof
    }

    struct Proof {
        Pairing.G1Point A;
        Pairing.G2Point B;
        Pairing.G1Point C;
    }

    function verifyingKey() internal pure returns (VerifyingKey memory vk) {
        vk.alfa1 = Pairing.G1Point(uint256(12857594084636618285544755944468985928964130149997412675072260253367063580435), uint256(4520463564105181032527031773627253947513450713102423248121805504972502265557));
        vk.beta2 = Pairing.G2Point([uint256(3768419101160861617576738923834270963576009272436365038149102536289484767663), uint256(2422359654092397605286516002492572179276729032830872006844863791580800181174)], [uint256(3561792767227689051565180404410972216016444591951495350942823926051158971137), uint256(5929735847947018210358411392731563478998308892959475643460648267591327576580)]);
        vk.gamma2 = Pairing.G2Point([uint256(10031321632035027041850604447896042479417191551955187564306555120737140701188), uint256(9246511652618527899733346379676127298551988345197300520547392750332843998776)], [uint256(1905630354282770091221043005247854936048104044907885551076540850339496121522), uint256(18225686710449879679600448102464653471805562080686110057451971323469567279999)]);
        vk.delta2 = Pairing.G2Point([uint256(16405073837390302942606939098691051365418147031898890601851987740415137638532), uint256(9407568642316524545225090415433694026960438805225880887774280298821722081434)], [uint256(10251709005672304814378972481146671011125275943428531360369642221565994121808), uint256(10978964683433301086043294068537857815948436622294536521024599694635688317493)]);
    }


    // accumulate scalarMul(mul_input) into q
    // that is computes sets q = (mul_input[0:2] * mul_input[3]) + q
    function accumulate(
        uint256[3] memory mul_input,
        Pairing.G1Point memory p,
        uint256[4] memory buffer,
        Pairing.G1Point memory q
    ) internal view {
        // computes p = mul_input[0:2] * mul_input[3]
        Pairing.scalar_mul_raw(mul_input, p);

        // point addition inputs
        buffer[0] = q.X;
        buffer[1] = q.Y;
        buffer[2] = p.X;
        buffer[3] = p.Y;

        // q = p + q
        Pairing.plus_raw(buffer, q);
    }

    /*
     * @returns Whether the proof is valid given the hardcoded verifying key
     *          above and the public inputs
     */
    function verifyProof(
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[36] memory input
    ) public view returns (bool r) {

        Proof memory proof;
        proof.A = Pairing.G1Point(a[0], a[1]);
        proof.B = Pairing.G2Point([b[0][0], b[0][1]], [b[1][0], b[1][1]]);
        proof.C = Pairing.G1Point(c[0], c[1]);

        // Make sure that proof.A, B, and C are each less than the prime q
        require(proof.A.X < PRIME_Q, "verifier-aX-gte-prime-q");
        require(proof.A.Y < PRIME_Q, "verifier-aY-gte-prime-q");

        require(proof.B.X[0] < PRIME_Q, "verifier-bX0-gte-prime-q");
        require(proof.B.Y[0] < PRIME_Q, "verifier-bY0-gte-prime-q");

        require(proof.B.X[1] < PRIME_Q, "verifier-bX1-gte-prime-q");
        require(proof.B.Y[1] < PRIME_Q, "verifier-bY1-gte-prime-q");

        require(proof.C.X < PRIME_Q, "verifier-cX-gte-prime-q");
        require(proof.C.Y < PRIME_Q, "verifier-cY-gte-prime-q");

        // Make sure that every input is less than the snark scalar field
        for (uint256 i = 0; i < input.length; i++) {
            require(input[i] < SNARK_SCALAR_FIELD,"verifier-gte-snark-scalar-field");
        }

        VerifyingKey memory vk = verifyingKey();

        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);

        // Buffer reused for addition p1 + p2 to avoid memory allocations
        // [0:2] -> p1.X, p1.Y ; [2:4] -> p2.X, p2.Y
        uint256[4] memory add_input;

        // Buffer reused for multiplication p1 * s
        // [0:2] -> p1.X, p1.Y ; [3] -> s
        uint256[3] memory mul_input;

        // temporary point to avoid extra allocations in accumulate
        Pairing.G1Point memory q = Pairing.G1Point(0, 0);

        vk_x.X = uint256(8765113096364851211295119303681930034441924204618948216473120806912544903970); // vk.K[0].X
        vk_x.Y = uint256(10123401272328655725300408742908287346416571900921099572599018193730316421052); // vk.K[0].Y
        mul_input[0] = uint256(11737010743097258685506887023729977686057340386466640611488614887406778466087); // vk.K[1].X
        mul_input[1] = uint256(9293788096103237121024206022564219729736632270623585090369666920809227491918); // vk.K[1].Y
        mul_input[2] = input[0];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[1] * input[0]
        mul_input[0] = uint256(6289685113888398859931065893339604074105497813574607689399923802378513397402); // vk.K[2].X
        mul_input[1] = uint256(6955827318103700818445754469407195085276452888426471800938562191297376287447); // vk.K[2].Y
        mul_input[2] = input[1];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[2] * input[1]
        mul_input[0] = uint256(4311252016637759958287496388193155697583177754702497400589310509498636339228); // vk.K[3].X
        mul_input[1] = uint256(15459290763571335182506642362807228694202182292258271986360029697585145704006); // vk.K[3].Y
        mul_input[2] = input[2];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[3] * input[2]
        mul_input[0] = uint256(10449525339506607959824354869702330006751562863963145642458242136383673859530); // vk.K[4].X
        mul_input[1] = uint256(19628934050322006206661202013691153133518701584150689614788231196649030824232); // vk.K[4].Y
        mul_input[2] = input[3];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[4] * input[3]
        mul_input[0] = uint256(14540810954725441938986088952861233613532182207626915121997256592573591176374); // vk.K[5].X
        mul_input[1] = uint256(16680831108002061302766461769424157284886874358104345970766173511989212081970); // vk.K[5].Y
        mul_input[2] = input[4];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[5] * input[4]
        mul_input[0] = uint256(11972826778811653441890533963433831910754129630028584316548311641042419859467); // vk.K[6].X
        mul_input[1] = uint256(3700342033437720230930368901239040640112814528623933983440352444930842399184); // vk.K[6].Y
        mul_input[2] = input[5];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[6] * input[5]
        mul_input[0] = uint256(12238096645261984514380294656959482785472135423418769109349301510988841515008); // vk.K[7].X
        mul_input[1] = uint256(14499016336669801633187234557847125536177925584703281397607731147312412513615); // vk.K[7].Y
        mul_input[2] = input[6];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[7] * input[6]
        mul_input[0] = uint256(18901924655790874911224257911888321660378945367836753867704371842031882916388); // vk.K[8].X
        mul_input[1] = uint256(1927239798257606567799499481962193812033659580666653588706745491816764762742); // vk.K[8].Y
        mul_input[2] = input[7];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[8] * input[7]
        mul_input[0] = uint256(14580424485429959916210658685761273800815683090281466103844294482678820969941); // vk.K[9].X
        mul_input[1] = uint256(11577155401897372425851140782068060769994086207869869927874978349940437095129); // vk.K[9].Y
        mul_input[2] = input[8];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[9] * input[8]
        mul_input[0] = uint256(16610950024863152534799725110556317303932805989853381653914405929474861565830); // vk.K[10].X
        mul_input[1] = uint256(5319943574258425837671794858713526805931562926690652114491036729616699425627); // vk.K[10].Y
        mul_input[2] = input[9];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[10] * input[9]
        mul_input[0] = uint256(16457264981361818292464202310758412379098497247691304462991941981598166166143); // vk.K[11].X
        mul_input[1] = uint256(8498690699261882215365952919021650926556036307074793366982999066749914709104); // vk.K[11].Y
        mul_input[2] = input[10];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[11] * input[10]
        mul_input[0] = uint256(7135664600066583290066593258341019973188930373613404604422412362988077269049); // vk.K[12].X
        mul_input[1] = uint256(17585104691553881179205560469299812770271311768372348344115497286549653881429); // vk.K[12].Y
        mul_input[2] = input[11];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[12] * input[11]
        mul_input[0] = uint256(19789509430681703624106165672619059149656147954127365821295903410884377462422); // vk.K[13].X
        mul_input[1] = uint256(14761018143114907972745262652094891771020583157558897600509501503851875050135); // vk.K[13].Y
        mul_input[2] = input[12];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[13] * input[12]
        mul_input[0] = uint256(8081563522291049379847478997817388861419785591765985942174421838989457995270); // vk.K[14].X
        mul_input[1] = uint256(16557452730315841792806457910715526032038536976966162408939341011892524371251); // vk.K[14].Y
        mul_input[2] = input[13];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[14] * input[13]
        mul_input[0] = uint256(6782604760068556991053829855370307415386214877341548759836319580090781181097); // vk.K[15].X
        mul_input[1] = uint256(16860848858944194067620871055875937124265534966142525883487649068107698168071); // vk.K[15].Y
        mul_input[2] = input[14];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[15] * input[14]
        mul_input[0] = uint256(15840904678840183464081325729316658826714071509463349711763082786372330691252); // vk.K[16].X
        mul_input[1] = uint256(5080634410775877975824874204336674077008177300479868553438574635945576864750); // vk.K[16].Y
        mul_input[2] = input[15];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[16] * input[15]
        mul_input[0] = uint256(10633588886397730129814786481587151790019371829655864072074605433459487331); // vk.K[17].X
        mul_input[1] = uint256(20703412401865051500690507135497260270177875437123723125081506334186616561855); // vk.K[17].Y
        mul_input[2] = input[16];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[17] * input[16]
        mul_input[0] = uint256(18998075187692689715669103430364813612543570835829614229988048088412815566164); // vk.K[18].X
        mul_input[1] = uint256(18266308943225381992465884513636550089448596926270248380770743170294572926155); // vk.K[18].Y
        mul_input[2] = input[17];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[18] * input[17]
        mul_input[0] = uint256(10470602895664330726789179185829194252867299972190642276118361862828897141148); // vk.K[19].X
        mul_input[1] = uint256(17473577620849984113722771516563814974234865816046571096767100800061912835908); // vk.K[19].Y
        mul_input[2] = input[18];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[19] * input[18]
        mul_input[0] = uint256(12585722954648576894987824318286323515014904754721434072138583104600955264050); // vk.K[20].X
        mul_input[1] = uint256(15314275712957122636414755924911550677047986822915626461626917604555368187625); // vk.K[20].Y
        mul_input[2] = input[19];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[20] * input[19]
        mul_input[0] = uint256(17698535109252931539430099571837280034119161553253348667289752106821167228978); // vk.K[21].X
        mul_input[1] = uint256(17679640052041933462178890180213722783341508081132126438302399030275429936776); // vk.K[21].Y
        mul_input[2] = input[20];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[21] * input[20]
        mul_input[0] = uint256(5929610351488141189371154202931112471169674651281091322157192358660457801882); // vk.K[22].X
        mul_input[1] = uint256(9232174698055594360778411982074970580864303354074400399797916464040883078367); // vk.K[22].Y
        mul_input[2] = input[21];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[22] * input[21]
        mul_input[0] = uint256(8741855965029454717147150765879072244136582366663196128921531577250095429618); // vk.K[23].X
        mul_input[1] = uint256(6940774063919964706981142311301786114662271355423334041095314047196134327048); // vk.K[23].Y
        mul_input[2] = input[22];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[23] * input[22]
        mul_input[0] = uint256(18273635423526444907905864163337842936841608382075611883507560372108001044017); // vk.K[24].X
        mul_input[1] = uint256(16573094799166114504514486286215803442221422877695698244448045309455742368602); // vk.K[24].Y
        mul_input[2] = input[23];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[24] * input[23]
        mul_input[0] = uint256(10531510239957292947803595892961399477018783972514633610686316311404411548467); // vk.K[25].X
        mul_input[1] = uint256(689425825071197357225086442514193675407120367667714045881395057487172690474); // vk.K[25].Y
        mul_input[2] = input[24];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[25] * input[24]
        mul_input[0] = uint256(11291799960917763551077279562100983375631373880201630408809129065197546092114); // vk.K[26].X
        mul_input[1] = uint256(21798472805029314876928584202970488955048673679067544619486675491308424689160); // vk.K[26].Y
        mul_input[2] = input[25];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[26] * input[25]
        mul_input[0] = uint256(16315258528296010693820009254041837122742404162630204339010037069994168422127); // vk.K[27].X
        mul_input[1] = uint256(2490428471841564333291928356154404452098743665893044635460180684011728866604); // vk.K[27].Y
        mul_input[2] = input[26];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[27] * input[26]
        mul_input[0] = uint256(5975487504883620955800843629603380248624307074806204428854473230725911030154); // vk.K[28].X
        mul_input[1] = uint256(21375632005544077775324853776249990338275439270506113707467655349457690180182); // vk.K[28].Y
        mul_input[2] = input[27];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[28] * input[27]
        mul_input[0] = uint256(14978246073691701969770789177970526513994010046513903986727818161609212376332); // vk.K[29].X
        mul_input[1] = uint256(10333316909011936860447681810274510397150855833251090353019686559545007962576); // vk.K[29].Y
        mul_input[2] = input[28];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[29] * input[28]
        mul_input[0] = uint256(2912497198002394427801319132213207277321467720319081899870259556900803959415); // vk.K[30].X
        mul_input[1] = uint256(3686961482087503084807467254669170410626081432341288071006188661250015451908); // vk.K[30].Y
        mul_input[2] = input[29];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[30] * input[29]
        mul_input[0] = uint256(11870084673762264560811253944692792176810087854344724517210187231627036204804); // vk.K[31].X
        mul_input[1] = uint256(13081848549870066896780369781404862580118532973058458832131605238609269481588); // vk.K[31].Y
        mul_input[2] = input[30];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[31] * input[30]
        mul_input[0] = uint256(15806831486149200120255780019763383461001278885419873251703108189298845234826); // vk.K[32].X
        mul_input[1] = uint256(9103004459424721510870038417139774031314300339786025969210788900860081728811); // vk.K[32].Y
        mul_input[2] = input[31];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[32] * input[31]
        mul_input[0] = uint256(13634575422151916711515760741024841937316959796083045806647083673982762468731); // vk.K[33].X
        mul_input[1] = uint256(5183336025109238237670151930129817744448931553089828534198049640381647230772); // vk.K[33].Y
        mul_input[2] = input[32];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[33] * input[32]
        mul_input[0] = uint256(1986413613219000770194364016148709244536775976398516762480174396107603219834); // vk.K[34].X
        mul_input[1] = uint256(3270987731693590881899033168135661596794679509110018970288221118433760140464); // vk.K[34].Y
        mul_input[2] = input[33];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[34] * input[33]
        mul_input[0] = uint256(15000643075487582888224780313338596127777269634531425480728292310200501023587); // vk.K[35].X
        mul_input[1] = uint256(21336346242692139702568631782466743527711570434665367616816450952491102554429); // vk.K[35].Y
        mul_input[2] = input[34];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[35] * input[34]
        mul_input[0] = uint256(2056391574823295437355041602171134859196579884880359538753378971938827473378); // vk.K[36].X
        mul_input[1] = uint256(3505106954763170085414800407685130491203578859911551316106069173866644765076); // vk.K[36].Y
        mul_input[2] = input[35];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[36] * input[35]

        return Pairing.pairing(
            Pairing.negate(proof.A),
            proof.B,
            vk.alfa1,
            vk.beta2,
            vk_x,
            vk.gamma2,
            proof.C,
            vk.delta2
        );
    }
}
