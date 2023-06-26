
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
        vk.alfa1 = Pairing.G1Point(uint256(1821465053934150165498016754632684520093501159851875391324072765188510250559), uint256(7640971627729865341432370426093833424528956952419770458829613480407338668693));
        vk.beta2 = Pairing.G2Point([uint256(8998512650221176946767517077471300142982499051709346844483904387744492929029), uint256(18969149187668111309272825130064794511612683531710959399294845970802797311648)], [uint256(6104782076219033176333638775815295830568850637251156789281815754700935799449), uint256(317881131696555068885862957922258307449238858455579085279786565366600123435)]);
        vk.gamma2 = Pairing.G2Point([uint256(7436472288612227284909521992584384265660886393650412525145841873146997184333), uint256(19160856161244326867096549518932731121809979646972306543874279224573021488266)], [uint256(1275493652992818556836719339273911736506315321230701996664169987946273809575), uint256(14573704357661621953014570549018562642262448286630780011149746068111616742006)]);
        vk.delta2 = Pairing.G2Point([uint256(12632892967608561837501151814894701389798086763479316895786098250672903266916), uint256(9641935001896516344381685216839910342532886855503478462027749044952557013986)], [uint256(21266024015992924132822869110857762636284269871943801074616391369604408870788), uint256(11959339414171870007220769318610101081445881509762866909059246890024042484697)]);
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

        vk_x.X = uint256(12231174827368729593371451207880656833371481450124302262045880501536433925691); // vk.K[0].X
        vk_x.Y = uint256(1015891180895908855673513846375264633081835858007958960011066386467945660535); // vk.K[0].Y
        mul_input[0] = uint256(618964450764758925245824147080714317287048178766925149214232620805186400227); // vk.K[1].X
        mul_input[1] = uint256(17291373041559835436811336148151556487600379500500760820078580528700305137194); // vk.K[1].Y
        mul_input[2] = input[0];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[1] * input[0]
        mul_input[0] = uint256(3252874080982289821248795306836563083211437779922776961913662044982051189262); // vk.K[2].X
        mul_input[1] = uint256(17471022353471519616268645776178204441771214911899370771716140321834304487043); // vk.K[2].Y
        mul_input[2] = input[1];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[2] * input[1]
        mul_input[0] = uint256(14847713067525760148241113037792747512316541906703945630606472225252958312969); // vk.K[3].X
        mul_input[1] = uint256(8690984053764522162780362375450300821782611456098981984905748572056912787179); // vk.K[3].Y
        mul_input[2] = input[2];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[3] * input[2]
        mul_input[0] = uint256(2807131110265338357990671991320359386563847298652009743254259662529569854344); // vk.K[4].X
        mul_input[1] = uint256(7033684914983028165427463836974346235941780141422502805281138044596727028415); // vk.K[4].Y
        mul_input[2] = input[3];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[4] * input[3]
        mul_input[0] = uint256(2119356909091597097660692433575390780065988783622875204381385156428080586078); // vk.K[5].X
        mul_input[1] = uint256(4472299563055824114232220037380205023186312953054897023715856837952024251952); // vk.K[5].Y
        mul_input[2] = input[4];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[5] * input[4]
        mul_input[0] = uint256(20029257650178189392196810344581490497334058574658037991527019510232470301873); // vk.K[6].X
        mul_input[1] = uint256(21684340012819620679943757999237724333350958954784854346175982760889593371850); // vk.K[6].Y
        mul_input[2] = input[5];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[6] * input[5]
        mul_input[0] = uint256(19623880734922402656059788819334313528051377784568970061968323984223649383431); // vk.K[7].X
        mul_input[1] = uint256(15459399141067663929004881578219931620269056372507201475030457571876931541142); // vk.K[7].Y
        mul_input[2] = input[6];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[7] * input[6]
        mul_input[0] = uint256(3540885416145806191027622415208511595684181966216446868593700737124606930230); // vk.K[8].X
        mul_input[1] = uint256(17044317045413724552446390437110058011060627745635901454377148169068590324836); // vk.K[8].Y
        mul_input[2] = input[7];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[8] * input[7]
        mul_input[0] = uint256(19802056624551984247405780992241222971895162510355006082630145334178751849403); // vk.K[9].X
        mul_input[1] = uint256(12335597219927170626616577892565559036069464148648697992624931081054093277128); // vk.K[9].Y
        mul_input[2] = input[8];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[9] * input[8]
        mul_input[0] = uint256(13712046772369947513084535851275495003010142624584251744014522890993802147354); // vk.K[10].X
        mul_input[1] = uint256(6612153177666009752873646039240476945583347538759752338729976502487066225948); // vk.K[10].Y
        mul_input[2] = input[9];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[10] * input[9]
        mul_input[0] = uint256(18887201091161832502130093878110279069148471837801408726907686768150570872194); // vk.K[11].X
        mul_input[1] = uint256(7331645662269820603174505449119561669569822149258798371799895211568762066522); // vk.K[11].Y
        mul_input[2] = input[10];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[11] * input[10]
        mul_input[0] = uint256(4099319438888951877186143830143286504284824321236451552915440436302461055712); // vk.K[12].X
        mul_input[1] = uint256(20221807267810677358057253525807155868217020442079338247759959457009263019635); // vk.K[12].Y
        mul_input[2] = input[11];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[12] * input[11]
        mul_input[0] = uint256(11435189642144623412525469930011867501405615550362461090657986633926095931455); // vk.K[13].X
        mul_input[1] = uint256(18659689277933050280080581933924598320638323105255797419600391836183552458168); // vk.K[13].Y
        mul_input[2] = input[12];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[13] * input[12]
        mul_input[0] = uint256(13829936348367799432973094278480379086557274622813201489742558700045098130535); // vk.K[14].X
        mul_input[1] = uint256(16963750793482170617407629800723597660083078148473426469543306659788220397835); // vk.K[14].Y
        mul_input[2] = input[13];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[14] * input[13]
        mul_input[0] = uint256(16119560960299363104640311793482597554177101458921853719443140019082688779797); // vk.K[15].X
        mul_input[1] = uint256(12315920210337586809980786107827576353027603866908623251764456371574645200757); // vk.K[15].Y
        mul_input[2] = input[14];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[15] * input[14]
        mul_input[0] = uint256(14626838714793554100273455349566530691093104526510525763343715691198801797634); // vk.K[16].X
        mul_input[1] = uint256(19713159414747556579009997224165571247109450463269898019237695056964087127558); // vk.K[16].Y
        mul_input[2] = input[15];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[16] * input[15]
        mul_input[0] = uint256(15891836249670934006337860842984929976527264730226087575439366060257879504851); // vk.K[17].X
        mul_input[1] = uint256(364428413306371979008196988091999905797014600466915725745012225664839190648); // vk.K[17].Y
        mul_input[2] = input[16];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[17] * input[16]
        mul_input[0] = uint256(16000456279089684112811071131965931857479793416980254143560050146736003799645); // vk.K[18].X
        mul_input[1] = uint256(7443443704507054113460163685440205018377617034575099590811029712652579719626); // vk.K[18].Y
        mul_input[2] = input[17];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[18] * input[17]
        mul_input[0] = uint256(16504058184517562434330931116515386587824440271800340485391470402998943961484); // vk.K[19].X
        mul_input[1] = uint256(19703770423380536896163596945990199566253579300527082377977368791417771923455); // vk.K[19].Y
        mul_input[2] = input[18];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[19] * input[18]
        mul_input[0] = uint256(6951924702893086678242057129263057620534407871902883107220939234288360382153); // vk.K[20].X
        mul_input[1] = uint256(5417346925921521042658734926888592092365885670003639203240347842496295955836); // vk.K[20].Y
        mul_input[2] = input[19];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[20] * input[19]
        mul_input[0] = uint256(17456079317479869892223365582788743559292180101912713318785767809029677662663); // vk.K[21].X
        mul_input[1] = uint256(6867015811437501543469839233298177651396876673221877568656705038491932978728); // vk.K[21].Y
        mul_input[2] = input[20];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[21] * input[20]
        mul_input[0] = uint256(10889596543591796165266324816586223429141872662843513369171447143075321019239); // vk.K[22].X
        mul_input[1] = uint256(15197135439459119059985359340139183556696710041911733263892068704108191390900); // vk.K[22].Y
        mul_input[2] = input[21];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[22] * input[21]
        mul_input[0] = uint256(21812469387775918350375226720757036996195892723727927437410382652504816112130); // vk.K[23].X
        mul_input[1] = uint256(9643715957176913379054072091635605679260866648049338618920788751950130968282); // vk.K[23].Y
        mul_input[2] = input[22];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[23] * input[22]
        mul_input[0] = uint256(6344949470761252872152519479508986160083759192071763034700472642203848427450); // vk.K[24].X
        mul_input[1] = uint256(2942489443246752364169708637918439633083602709065282903860298334621686534212); // vk.K[24].Y
        mul_input[2] = input[23];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[24] * input[23]
        mul_input[0] = uint256(16490933693020968287482300046302195105288077986494852598795638392200878160793); // vk.K[25].X
        mul_input[1] = uint256(19661335695504023190295865006972573545638747948457938905466071463924735090450); // vk.K[25].Y
        mul_input[2] = input[24];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[25] * input[24]
        mul_input[0] = uint256(6632474033100511374359234592419378157536923240066563809072262841052674763896); // vk.K[26].X
        mul_input[1] = uint256(3544004472249738022137135124299328174821479967720921635382103570134269356217); // vk.K[26].Y
        mul_input[2] = input[25];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[26] * input[25]
        mul_input[0] = uint256(16216962930078035379143632818705402332438329086249532870240515781617224672146); // vk.K[27].X
        mul_input[1] = uint256(13584576413063178858593814043637339552594769074594330077759942865360433742981); // vk.K[27].Y
        mul_input[2] = input[26];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[27] * input[26]
        mul_input[0] = uint256(5137982978535900848376921194227497487181552882588009959241232038781751577001); // vk.K[28].X
        mul_input[1] = uint256(13507509390993124844293331003788063615577617718022480955604225461930209468307); // vk.K[28].Y
        mul_input[2] = input[27];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[28] * input[27]
        mul_input[0] = uint256(18714523577334618088759314520538563880956146325520275892308752813022005287844); // vk.K[29].X
        mul_input[1] = uint256(775942594403113067969726411239236489528150892420220476451352061526447961456); // vk.K[29].Y
        mul_input[2] = input[28];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[29] * input[28]
        mul_input[0] = uint256(17035354696001541318355915887495300518636567303638531071147400569897773771966); // vk.K[30].X
        mul_input[1] = uint256(13418053929151219007564783460735996779111847035276612406942454532832256635923); // vk.K[30].Y
        mul_input[2] = input[29];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[30] * input[29]
        mul_input[0] = uint256(19811107987554130525241484866446089773217295553860602224988124645159953735781); // vk.K[31].X
        mul_input[1] = uint256(10287742430801732873296437253671733911954101057804529875862594472583582532854); // vk.K[31].Y
        mul_input[2] = input[30];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[31] * input[30]
        mul_input[0] = uint256(21408651148071023251084981539403484437160955009585328174430769808091652268152); // vk.K[32].X
        mul_input[1] = uint256(12633626570060742850094541876547026504848613206784939052064532742263726469974); // vk.K[32].Y
        mul_input[2] = input[31];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[32] * input[31]
        mul_input[0] = uint256(21860411913159779884223359910788935168421866288170907837208167889668509946865); // vk.K[33].X
        mul_input[1] = uint256(1223937381811023846815945905528732032460401418010055897079302078272460677009); // vk.K[33].Y
        mul_input[2] = input[32];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[33] * input[32]
        mul_input[0] = uint256(18764396498584968270465177767888419593009253312580851567829750658536082313169); // vk.K[34].X
        mul_input[1] = uint256(6515228102776436515111363402069155853390842981533970875433207631861461186069); // vk.K[34].Y
        mul_input[2] = input[33];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[34] * input[33]
        mul_input[0] = uint256(8181088486303089929987332499944396049464451373602617856480986894406242065074); // vk.K[35].X
        mul_input[1] = uint256(6996590502503098947214180067290593514101893797754016177020320233889704637062); // vk.K[35].Y
        mul_input[2] = input[34];
        accumulate(mul_input, q, add_input, vk_x); // vk_x += vk.K[35] * input[34]
        mul_input[0] = uint256(13889498770477082201602003230797885425837968722129684800456914667451661137884); // vk.K[36].X
        mul_input[1] = uint256(15049053490273871787821877854329626856017398996182451223938306970706032373127); // vk.K[36].Y
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
