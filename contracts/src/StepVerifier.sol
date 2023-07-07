
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
        vk.alfa1 = Pairing.G1Point(uint256(12116571301211491853004588731308269648524949641358064564655444056918835033185), uint256(9101449513826569759883854751045718306034786884115228952007471379135645986582));
        vk.beta2 = Pairing.G2Point([uint256(3201541606198532310155402026749266712122581729623181201929898939149328624372), uint256(20288166996034225648530288995239954425547465977658377628729954185263296739036)], [uint256(3863257346009066461998647767093983607002418479514839053266313506557869859474), uint256(8328879089127133529601046458955944084634738684741970875729693050977837388790)]);
        vk.gamma2 = Pairing.G2Point([uint256(12404795020594004973655108448740702311528776260848721091344636602434422310807), uint256(13492896910194390244953453161369473953041572264251296735324984382088222321226)], [uint256(13787752825018589344379943136835080057128498310664677190901771315445941232883), uint256(11078522508015029981832379483995879232479460413148157587549435117785354541417)]);
        vk.delta2 = Pairing.G2Point([uint256(3803002658918119078123336411220714046268144972434816333020589922815948900007), uint256(18263135412719726414127342021762501158689427898678793738648882470881688110346)], [uint256(251720849166087020974970534122893055546296518223732326284640589164573209550), uint256(20649049227841416368337503600103615494842285965694317410981218572489418273900)]);
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

        vk_x.X = uint256(14975144162639797205349568284085185203670152580587541830305715312606332856220); // vk.K[0].X
        vk_x.Y = uint256(16050216035789678467847321489275062289203633189231312389089523790466061766932); // vk.K[0].Y
        mul_input[0] = uint256(2504984908942232115831644767495808444864102407288618858059817012872796266859); // vk.K[1].X
        mul_input[1] = uint256(21129406050878549590537592868270019779631791340519825981586744690700483094694); // vk.K[1].Y
        mul_input[2] = input[0];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[1] * input[0]
        mul_input[0] = uint256(10347399299226667003725471426276245078305126206648540728863078728099756689509); // vk.K[2].X
        mul_input[1] = uint256(8884212450754136379184387086346519721325681787689992196907977898196935433347); // vk.K[2].Y
        mul_input[2] = input[1];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[2] * input[1]
        mul_input[0] = uint256(6349482230697136291196315121910514158337655142211658034404454331252164178657); // vk.K[3].X
        mul_input[1] = uint256(12041238896154376389025812159724017845801721137661965347961163894372573612928); // vk.K[3].Y
        mul_input[2] = input[2];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[3] * input[2]
        mul_input[0] = uint256(12008710521769269038310996945255673481806081749826441374939220168946854225240); // vk.K[4].X
        mul_input[1] = uint256(21443685355010611891167380892714431524032443299434649741453495978161442975941); // vk.K[4].Y
        mul_input[2] = input[3];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[4] * input[3]
        mul_input[0] = uint256(9504756460674180275887858397110016798288976192502498665406397851718751849427); // vk.K[5].X
        mul_input[1] = uint256(7828454447134888386979801730271762371485117326076573335485553050671248781914); // vk.K[5].Y
        mul_input[2] = input[4];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[5] * input[4]
        mul_input[0] = uint256(7162518249356925445331932832768843583011912440508646618964294965182836978469); // vk.K[6].X
        mul_input[1] = uint256(4143585897086655641400694660112968900039775145578243882854548872622328578004); // vk.K[6].Y
        mul_input[2] = input[5];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[6] * input[5]
        mul_input[0] = uint256(12716735807321790901816631553164387488552051124514642303400775772593922722551); // vk.K[7].X
        mul_input[1] = uint256(13901196276990368657260149699199202183825414781263973704785863065338190631947); // vk.K[7].Y
        mul_input[2] = input[6];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[7] * input[6]
        mul_input[0] = uint256(4952594092669536773924614685091138401695425197987912029124413633972395444859); // vk.K[8].X
        mul_input[1] = uint256(6592936540216403348344112627589398831098128108105798489331419076382482575429); // vk.K[8].Y
        mul_input[2] = input[7];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[8] * input[7]
        mul_input[0] = uint256(16010926026295896259493288721605393310045456851734561263316739942826478481319); // vk.K[9].X
        mul_input[1] = uint256(20426810144938974696856330623204809743076906435808812794212229775686152830658); // vk.K[9].Y
        mul_input[2] = input[8];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[9] * input[8]
        mul_input[0] = uint256(19918067422855566717861529460104128095989335827144586994272924206713942338108); // vk.K[10].X
        mul_input[1] = uint256(1189559172416661138849379238627292729398844873114516228412234311736031732099); // vk.K[10].Y
        mul_input[2] = input[9];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[10] * input[9]
        mul_input[0] = uint256(17019013289438982117939889268415156788778610736561265036383150993772573877632); // vk.K[11].X
        mul_input[1] = uint256(19209802095016798118162403882253015284540508133007147418572419242268036445302); // vk.K[11].Y
        mul_input[2] = input[10];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[11] * input[10]
        mul_input[0] = uint256(3340921672008193320426942064105161869463551395762451221796235556228965369382); // vk.K[12].X
        mul_input[1] = uint256(344793194099159545957085831755549532891503985383107529432628798681238385024); // vk.K[12].Y
        mul_input[2] = input[11];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[12] * input[11]
        mul_input[0] = uint256(3723646651515446251447108671561037327807456281130530121508515389478933473052); // vk.K[13].X
        mul_input[1] = uint256(15440431128056961255639631272566726742006332095854609581365588536587850215694); // vk.K[13].Y
        mul_input[2] = input[12];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[13] * input[12]
        mul_input[0] = uint256(8689455452365453187810684620718718827470400926412853313096989393461832578832); // vk.K[14].X
        mul_input[1] = uint256(11453833325145785453487726716924621256989380066277675615011025242745460451951); // vk.K[14].Y
        mul_input[2] = input[13];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[14] * input[13]
        mul_input[0] = uint256(1602674705934331227180103686160469380732512848751073884041997856952948434855); // vk.K[15].X
        mul_input[1] = uint256(19244220401819044938236523927796949568907525883378909277298123747208282379476); // vk.K[15].Y
        mul_input[2] = input[14];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[15] * input[14]
        mul_input[0] = uint256(10916550373358787458779892870172674355462791400758577253304597988745198354540); // vk.K[16].X
        mul_input[1] = uint256(1525973283340320537468282992998378702337931867902591637433126445909484654025); // vk.K[16].Y
        mul_input[2] = input[15];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[16] * input[15]
        mul_input[0] = uint256(9606008395354386262610825468874719123494322971283753575861001621870198752666); // vk.K[17].X
        mul_input[1] = uint256(315590833461894962374249412820152145963415948870628383011842924579252232161); // vk.K[17].Y
        mul_input[2] = input[16];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[17] * input[16]
        mul_input[0] = uint256(1716506443674788740149796882633265915937226612415201270617300296660952747705); // vk.K[18].X
        mul_input[1] = uint256(217760368351964317608851941321143769366059437664645854212506105923549018526); // vk.K[18].Y
        mul_input[2] = input[17];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[18] * input[17]
        mul_input[0] = uint256(18177686245722628235389621528660822364742367687601708467726523231699929075568); // vk.K[19].X
        mul_input[1] = uint256(11211608361822084629958643301800629458860513439203332931383461687379312362771); // vk.K[19].Y
        mul_input[2] = input[18];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[19] * input[18]
        mul_input[0] = uint256(14433683463933171528174592059652621620192949366669465205144190962986803138202); // vk.K[20].X
        mul_input[1] = uint256(8920217394495555142837458797240263291174561020134290301942726506400353327757); // vk.K[20].Y
        mul_input[2] = input[19];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[20] * input[19]
        mul_input[0] = uint256(8559662985172636705842530424730478535297858743163029865121548867975339196061); // vk.K[21].X
        mul_input[1] = uint256(19407122682667924600330330672712481133857934738123650652889327483864436135807); // vk.K[21].Y
        mul_input[2] = input[20];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[21] * input[20]
        mul_input[0] = uint256(13606924546454138232249402519801457795130216586892694416893743043116503610646); // vk.K[22].X
        mul_input[1] = uint256(3791638026557132737473863991707412854673987383389650225558694354808207477448); // vk.K[22].Y
        mul_input[2] = input[21];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[22] * input[21]
        mul_input[0] = uint256(3078463520765809192746225197387413638103314255015171248778076280167202172981); // vk.K[23].X
        mul_input[1] = uint256(6638581398685436943342551830118139953130351275772247741441024925181937937673); // vk.K[23].Y
        mul_input[2] = input[22];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[23] * input[22]
        mul_input[0] = uint256(9089341906706688911903911807555291420719904279812267241069381833504569168406); // vk.K[24].X
        mul_input[1] = uint256(1410718146108006305664888764293670528692472359251159922189003615282403502042); // vk.K[24].Y
        mul_input[2] = input[23];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[24] * input[23]
        mul_input[0] = uint256(7341256128292137921895395257684242998707745995842308439096690980163124529891); // vk.K[25].X
        mul_input[1] = uint256(18441035285858774594173222264848596056353206810076875650555692742332230276194); // vk.K[25].Y
        mul_input[2] = input[24];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[25] * input[24]
        mul_input[0] = uint256(15582062706338094647720169981992001458660812715353158674013309829667353347181); // vk.K[26].X
        mul_input[1] = uint256(5535363330138557036528128166998045599729028151085157642145821431494057764146); // vk.K[26].Y
        mul_input[2] = input[25];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[26] * input[25]
        mul_input[0] = uint256(18656927153218946456477817921945699634139023463472804662546007970159337771264); // vk.K[27].X
        mul_input[1] = uint256(8482544738938074614683155933184536538965927468434566835276628496992561040433); // vk.K[27].Y
        mul_input[2] = input[26];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[27] * input[26]
        mul_input[0] = uint256(5400379623309745703732112467614660796174928339278461837783917391553823039739); // vk.K[28].X
        mul_input[1] = uint256(16186443558500176199734393782880642931775726082562875661972046497001085728529); // vk.K[28].Y
        mul_input[2] = input[27];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[28] * input[27]
        mul_input[0] = uint256(4573589688643343432709454071612663818886330939904758191380705688514478839629); // vk.K[29].X
        mul_input[1] = uint256(82005907810726233257179857344376860548074366222525218074395890726143867411); // vk.K[29].Y
        mul_input[2] = input[28];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[29] * input[28]
        mul_input[0] = uint256(2422835045413318988575235587760566036815478108221589870424265722250233229021); // vk.K[30].X
        mul_input[1] = uint256(1190655610042190041186425062960092088763217618532169848951504455540268092116); // vk.K[30].Y
        mul_input[2] = input[29];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[30] * input[29]
        mul_input[0] = uint256(3994953244644507373925166497456790354720952130519362530556439280494610633454); // vk.K[31].X
        mul_input[1] = uint256(6727051831339634694508546862684521841401553790142897985114321230157856126121); // vk.K[31].Y
        mul_input[2] = input[30];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[31] * input[30]
        mul_input[0] = uint256(14999270476534063716576980631104182958683460461730162402140832621000735068281); // vk.K[32].X
        mul_input[1] = uint256(2170990515737206392814287105748884880514343939825869618795824857088334521417); // vk.K[32].Y
        mul_input[2] = input[31];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[32] * input[31]
        mul_input[0] = uint256(9059521692952940486163765168756289655734716702604224662768119209173763144955); // vk.K[33].X
        mul_input[1] = uint256(13354173160157815687535909479605484829916708587461227921159919619085502957990); // vk.K[33].Y
        mul_input[2] = input[32];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[33] * input[32]
        mul_input[0] = uint256(17135519865976312417333379555883245994228178232534310726600800342665327039233); // vk.K[34].X
        mul_input[1] = uint256(8801684380336909445063673490364662345531038363938613881809032905212434614041); // vk.K[34].Y
        mul_input[2] = input[33];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[34] * input[33]
        mul_input[0] = uint256(9811652167558294971038535062194496317789614036098656057894892419013385572104); // vk.K[35].X
        mul_input[1] = uint256(15435980551427525245664036444304046406808036353580493490046893003774224851543); // vk.K[35].Y
        mul_input[2] = input[34];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[35] * input[34]
        mul_input[0] = uint256(9701512017125373887085107524478234942675481754270403369211038056764144344023); // vk.K[36].X
        mul_input[1] = uint256(1236419863161311094295150863916828850862331518029600668238608843303561737143); // vk.K[36].Y
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
