
// ###################################################################### //
//                          PRINCE CIPHER ENCRYPTION                      //  
//                         64-bit block, 128-bit key                      //
// ###################################################################### //

// Each Cipher output is CIPHER_WIDTH wide
module PRINCE #
    (
    parameter CIPHER_WIDTH      = 64, 				   // PRINCE is a 64-bit block cipher
    parameter CIPHER_LATENCY    = 5                    // the # of pipeline stages
    )   
    (
    input                       sys_rst,                // Common port for all controllers
    input                       clk,
    input                       CIPHER_GEN_EN,
    input [CIPHER_WIDTH-1:0]    KEY, 
    input [CIPHER_WIDTH-1:0]    IV,
    input [CIPHER_WIDTH-1:0]    PLAIN_TEXT,             // To leave blank for CNT/GCM mode

    output [CIPHER_WIDTH-1:0]   CIPHER_TEXT             // Last stage of CIPHER Gen pipeline
    );


// ...................................................................... //
//                          PRINCE algorithm        
//              
// KEY = (K1 || K0)
// K0' = L(K0) = (K0 >>> 1) ^ (K0 >> 63)
//
// (msg ^ K0) -> PRINCE_core -> (^ K0') = cipher
//
// PRINCE_core: full 12 rounds
//      (^ K1 ^ RC0) 	-> R1 -> R2 -> R3 -> R4 -> R5 
//              		-> S -> M' -> S_inv 
//                  	-> R6 -> R7 -> R8 -> R9 -> R10 
//														-> (^ RC11 ^ K1)
//
//	Reduced version of 5 rounds
//		(^ K1 ^ RC0) 	-> R1 -> R2 -> S -> M' -> S_inv -> (^ RC11 ^ K1)
//
//-------
// Ri, i <= 5:     S -> M -> ^ RCi ^ K1
// Ri, i >= 6:     ^ RCi ^ K1 -> M_inv -> S_inv 
//
//-------
// S-box: 
//	S:
//		   x: 0 1 2 3 4 5 6 7 8 9 A B C D E F
//	 	S(x): B F 3 2 A C 9 1 6 7 8 0 E 5 D 4
//
//	S_inv:
//		   x: B F 3 2 A C 9 1 6 7 8 0 E 5 D 4
//	S_inv(x): 0 1 2 3 4 5 6 7 8 9 A B C D E F
//
//-------
// RCi:
// 		RC0 = 64'h0000000000000000
//		RC1 = 64'h13198a2e03707344
//		RC2 = 64'ha4093822299f31d0
// 		RC3 = 64'h082efa98ec4e6c89
//		RC4 = 64'h452821e638d01377
//		RC5 = 64'hbe5466cf34e90c6c
// 		RC6 = 64'h7ef84f78fd955cb1
//		RC7 = 64'h85840851f1ac43aa
//		RC8 = 64'hc882d32f25323c54
// 		RC9 = 64'h64a51195e0e3610d
//		RC10= 64'hd3b5a399ca0c2399
//		RC11= 64'hc0ac29b7c97c50dd
//
//-------
// M = SR * M'
//	SR: 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 -> 0 5 10 15 4 9 14 3 8 13 2 7 12 1 6 11
//	
//	M': M0	0	0	0
//		0	M1	0	0
//		0	0	M1	0
//		0	0	0	M0
//
//		M0 = m0 m1 m2 m3
//		 	 m1 m2 m3 m0
//		 	 m2 m3 m0 m1
//		 	 m3 m0 m1 m2
//
//		M1 = m1 m2 m3 m0
//		 	 m2 m3 m0 m1
//		 	 m3 m0 m1 m2
//		 	 m0 m1 m2 m3
//
//		m0 = 0000, 0100, 0010, 0001
//		m1 = 1000, 0000, 0010, 0001
//		m2 = 1000, 0100, 0000, 0001
//		m3 = 1000, 0100, 0010, 0000
//
//
// ....................................................................... //




// ..................... KEY prep ........................... //
// KEY = K1 || K0
wire [63:0] K0;
wire [63:0] K1;
assign K0 = KEY[63:0];
assign K1 = KEY[127:64];

// K0' = L(K0) = (K0 >>> 1) ^ (K0 >> 63)
wire [63:0] K0_PRIME;     
assign K0_PRIME = (K0 >>> 1) ^ (K0 >> 63);

// Key extension: KEY_EXT = {K1, K0_Transform, K0}
wire [191:0] KEY_EXT;        
assign KEY_EXT = {K1, K0_PRIME, K0};


// ..................... RC constants ........................... //
parameter [63:0] RC [0:11] = 	{
									64'h0000000000000000,
									64'h13198a2e03707344,
									64'ha4093822299f31d0,
									64'h082efa98ec4e6c89,
									64'h452821e638d01377,
									64'hbe5466cf34e90c6c,
									64'h7ef84f78fd955cb1,
									64'h85840851f1ac43aa,
									64'hc882d32f25323c54,
									64'h64a51195e0e3610d,
									64'hd3b5a399ca0c2399,
									64'hc0ac29b7c97c50dd	
								};


// ..................... SBOX ........................... //
parameter [3:0] SBOX [0:4] = 	{	
									4'hB, 	// 0
									4'hF, 	// 1
									4'h3,  	// 2
									4'h2,  	// 3
									4'hA,  	// 4
									4'hC,  	// 5
									4'h9,  	// 6
									4'h1,  	// 7
									4'h6,  	// 8
									4'h7,  	// 9
									4'h8,  	// A
									4'h0,  	// B
									4'hE,  	// C
									4'h5,  	// D
									4'hD,  	// E
									4'h4 	// F
								};

parameter [3:0] SBOX_INV [0:4] = {	
									4'hB, 	// 0
									4'h7, 	// 1
									4'h3,  	// 2
									4'h2,  	// 3
									4'hF,  	// 4
									4'hD,  	// 5
									4'h8,  	// 6
									4'h9,  	// 7
									4'hA,  	// 8
									4'h6,  	// 9
									4'h4,  	// A
									4'h0,  	// B
									4'h5,  	// C
									4'hE,  	// D
									4'hC,  	// E
									4'h1 	// F
								};
 


// ..................... One Layer ........................... //




reg [CIPHER_WIDTH-1:0] CIPHER_STATE [0:CIPHER_LATENCY-1];






// --------------------------------------------------------------
endmodule