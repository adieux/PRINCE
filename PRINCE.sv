// ###################################################################### //
//                          PRINCE CIPHER ENCRYPTION                      //  
//                         64-bit block, 128-bit key                      //
// ###################################################################### //

// Each Cipher output is CIPHER_WIDTH wide
module PRINCE #
    (
    parameter CIPHER_WIDTH      = 64, 				   // PRINCE is a 64-bit block cipher
    parameter CIPHER_LATENCY    = 5                    // the # of pipeline stages, must be odd
    )   
    (
    input                       sys_rst,                // Common port for all controllers
    input                       clk,
    input                       PRINCE_EN,				// keep working if this is high
    input [CIPHER_WIDTH-1:0]    KEY, 
    input [CIPHER_WIDTH-1:0]    PRINCE_IV,				// Either the IV at CIPHER_GEN_EN, 
    													// or the incremented IV in the following 3 cycles
    input [CIPHER_WIDTH-1:0]    PLAIN_TEXT,             // To leave blank for CNT/GCM mode

    output [CIPHER_WIDTH-1:0]   CIPHER_TEXT             // Final cipher output
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
//		S -> M' -> S_inv can be 1 or 2 rounds, here we use 1 round
//
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
//							OR
//		      0 1 2 3 4 5 6 7 8 9 A B C D E F
//			  B 7 3 2 F D 8 9 A 6 4 0 5 E C 1
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
//	SR: 		0  1  2   3   4  5  6   7  8  9   10  11  12  13  14  15 
//			 -> 0  5  10  15  4  9  14  3  8  13  2   7   12  1   6   11
//	 			0 1 2 3 4 5 6 7 8 9 A B C D E F 
//			 -> 0 5 A F 4 9 E 3 8 D 2 7 C 1 6 B
//
//	SR_inv: 	0  1  2   3   4  5  6   7  8  9   10  11  12  13  14  15 
//			 -> 0  13 10  7   4  1  14  11 8  5   2   15  12  9   6   3   
//				0 1 2 3 4 5 6 7 8 9 A B C D E F 
//			 -> 0 D A 7 4 1 E B 8 5 2 F C 9 6 3
//
// M_inv = SR_inv * M'
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
//		   x: 0 1 2 3 4 5 6 7 8 9 A B C D E F
//	 	S(x): B F 3 2 A C 9 1 6 7 8 0 E 5 D 4
parameter [3:0] SBOX [0:15] = 	{	
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

//	S_inv:
//		   x: B F 3 2 A C 9 1 6 7 8 0 E 5 D 4
//	S_inv(x): 0 1 2 3 4 5 6 7 8 9 A B C D E F
//							OR
//		      0 1 2 3 4 5 6 7 8 9 A B C D E F
//			  B 7 3 2 F D 8 9 A 6 4 0 5 E C 1
parameter [3:0] SBOX_INV [0:15] = {	
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



// Pipeline registers
reg [CIPHER_WIDTH-1:0] CIPHER_STATE [0:CIPHER_LATENCY-1];


// Input to PRINCE core
wire [CIPHER_WIDTH-1:0]	KEY_WHITEN;
assign KEY_WHITEN = IV ^ RC[0] ^ K1;

// Final cipher output
assign CIPHER_TEXT = CIPHER_STATE[CIPHER_LATENCY-1] ^ RC[11] ^ K1;


// M'
// Which m does not participate in computation
parameter [3:0] MISS [0:15] = {
								4'b0111,
								4'b1011,
								4'b1101,
								4'b1110,

								4'b1110,
								4'b0111,
								4'b1011,
								4'b1101,

								4'b1101,
								4'b1110,
								4'b0111,
								4'b1011,

								4'b1011,
								4'b1101,
								4'b1110,
								4'b0111
							}



// Parameterizable PRINCE cipher gen
genvar STAGE;

generate 
    for (STAGE = 0; STAGE <= CIPHER_LATENCY - 1; STAGE = STAGE + 1)
    begin
        always @ (posedge clk)
        begin
            if (sys_rst)
                CIPHER_STATE[STAGE] <= 0;
            
            // Thus PRINCE_EN should stay on till it finishes all CIPHER_LATENCY rounds
            else if (PRINCE_EN)
            begin
            	// -------- The forward stages -------- 		
            	if ((STAGE < ((CIPHER_LATENCY-1) >> 1)) && STAGE >= 0)		
            	begin

            		// 1st stage, R0 taking IV as the input
            		// Ri, i <= 5:     S -> M -> ^ RCi ^ K1
            		if (STAGE == 0) 
            		begin
            			integer i, j;
						for (j=0; j<4; j=j+1)
							for (i=0; i<16; i=i+1)
								CIPHER_STATE[STAGE][j*16+i] 
									<= 	( 
											// 	SBOX  			SR 					  	  #M'_row 	missing
											// 															     if this is M1 or M0
											(SBOX[KEY_WHITEN[(j*16+ 3)%64 : (j*16+ 0)%64]][i % 4] & MISS[(i+(j[1]^j[0])*4)%16][0]) 	^
											(SBOX[KEY_WHITEN[(j*16+23)%64 : (j*16+20)%64]][i % 4] & MISS[(i+(j[1]^j[0])*4)%16][1]) 	^
											(SBOX[KEY_WHITEN[(j*16+43)%64 : (j*16+40)%64]][i % 4] & MISS[(i+(j[1]^j[0])*4)%16][2]) 	^
											(SBOX[KEY_WHITEN[(j*16+63)%64 : (j*16+60)%64]][i % 4] & MISS[(i+(j[1]^j[0])*4)%16][3]) 	
										) 
										^ RC[STAGE][j*16+i] ^ K1[j*16+i];
            		end // STAGE == 0


            		// Other forward stages
            		else if (STAGE < ((CIPHER_LATENCY-1) >> 1))
            		begin
						integer i, j;
						for (j=0; j<4; j=j+1)
							for (i=0; i<16; i=i+1)
								CIPHER_STATE[STAGE][j*16+i] 
									<= 	( 
											// 	SBOX  						SR 					  	 #M'_row 	missing
											// 															                if this is M1 or M0
											(SBOX[CIPHER_STATE[STAGE-1][(j*16+ 3)%64 : (j*16+ 0)%64]][i % 4] & MISS[(i+(j[1]^j[0])*4)%16][0]) 	^
											(SBOX[CIPHER_STATE[STAGE-1][(j*16+23)%64 : (j*16+20)%64]][i % 4] & MISS[(i+(j[1]^j[0])*4)%16][1]) 	^
											(SBOX[CIPHER_STATE[STAGE-1][(j*16+43)%64 : (j*16+40)%64]][i % 4] & MISS[(i+(j[1]^j[0])*4)%16][2]) 	^
											(SBOX[CIPHER_STATE[STAGE-1][(j*16+63)%64 : (j*16+60)%64]][i % 4] & MISS[(i+(j[1]^j[0])*4)%16][3]) 	
										)
										^ RC[STAGE][j*16+i] ^ K1[j*16+i];
            		end // STATE < ((CIPHER_LATENCY-1) >> 1)

            	end //  -------- All forward stages -------- 		





            	
            	// -------- Middle stage --------
            	// -> S -> M' -> S_inv 
            	integer i, j;
					for (j=0; j<16; j=j+1)
						CIPHER_STATE[STAGE][j*4+3 : j*4]  
							<= SBOX_INV	[
											{
												// 	SBOX  								   #M'_row 	          missing
												//		SBOX 										M'		  who's missing  M1 or M0
												// BIT 3
											   (
											   	(SBOX[CIPHER_STATE[STAGE-1][(j*16+ 3) : (j*16+ 0)]][3] & MISS[(j[1:0]*4+3 +(j[2]^j[3])*4)%16][0]) 	^
												(SBOX[CIPHER_STATE[STAGE-1][(j*16+ 7) : (j*16+ 4)]][3] & MISS[(j[1:0]*4+3 +(j[2]^j[3])*4)%16][1]) 	^
												(SBOX[CIPHER_STATE[STAGE-1][(j*16+11) : (j*16+ 8)]][3] & MISS[(j[1:0]*4+3 +(j[2]^j[3])*4)%16][2]) 	^
												(SBOX[CIPHER_STATE[STAGE-1][(j*16+15) : (j*16+12)]][3] & MISS[(j[1:0]*4+3 +(j[2]^j[3])*4)%16][3])
												),

											   // BIT 2
											   (
											   	(SBOX[CIPHER_STATE[STAGE-1][(j*16+ 3) : (j*16+ 0)]][2] & MISS[(j[1:0]*4+2 +(j[2]^j[3])*4)%16][0]) 	^
												(SBOX[CIPHER_STATE[STAGE-1][(j*16+ 7) : (j*16+ 4)]][2] & MISS[(j[1:0]*4+2 +(j[2]^j[3])*4)%16][1]) 	^
												(SBOX[CIPHER_STATE[STAGE-1][(j*16+11) : (j*16+ 8)]][2] & MISS[(j[1:0]*4+2 +(j[2]^j[3])*4)%16][2]) 	^
												(SBOX[CIPHER_STATE[STAGE-1][(j*16+15) : (j*16+12)]][2] & MISS[(j[1:0]*4+2 +(j[2]^j[3])*4)%16][3])
												),

											   // BIT 1
											   (
											   	(SBOX[CIPHER_STATE[STAGE-1][(j*16+ 3) : (j*16+ 0)]][1] & MISS[(j[1:0]*4+1 +(j[2]^j[3])*4)%16][0]) 	^
												(SBOX[CIPHER_STATE[STAGE-1][(j*16+ 7) : (j*16+ 4)]][1] & MISS[(j[1:0]*4+1 +(j[2]^j[3])*4)%16][1]) 	^
												(SBOX[CIPHER_STATE[STAGE-1][(j*16+11) : (j*16+ 8)]][1] & MISS[(j[1:0]*4+1 +(j[2]^j[3])*4)%16][2]) 	^
												(SBOX[CIPHER_STATE[STAGE-1][(j*16+15) : (j*16+12)]][1] & MISS[(j[1:0]*4+1 +(j[2]^j[3])*4)%16][3])
												),

											   // BIT 0
											   (
											   	(SBOX[CIPHER_STATE[STAGE-1][(j*16+ 3) : (j*16+ 0)]][0] & MISS[(j[1:0]*4+0 +(j[2]^j[3])*4)%16][0]) 	^
												(SBOX[CIPHER_STATE[STAGE-1][(j*16+ 7) : (j*16+ 4)]][0] & MISS[(j[1:0]*4+0 +(j[2]^j[3])*4)%16][1]) 	^
												(SBOX[CIPHER_STATE[STAGE-1][(j*16+11) : (j*16+ 8)]][0] & MISS[(j[1:0]*4+0 +(j[2]^j[3])*4)%16][2]) 	^
												(SBOX[CIPHER_STATE[STAGE-1][(j*16+15) : (j*16+12)]][0] & MISS[(j[1:0]*4+0 +(j[2]^j[3])*4)%16][3])
												) 	
											}
										]



        		else if (STAGE == ((CIPHER_LATENCY-1) >> 1))
        		begin
					integer i, j;
					for (j=0; j<4; j=j+1)
						for (i=0; i<16; i=i+4)
							CIPHER_STATE[STAGE][j*16+i+3 : j*16+i] 
								<= 	SBOX_INV[ 
										{

										}
									];

        		end // -------- Middle stage --------


        		

        		
        		
        		// -------- Reverse stages -------- 

        		// Ri, i >= 6:     ^ RCi ^ K1 -> M_inv -> S_inv 
        		else if (STAGE > ((CIPHER_LATENCY-1) >> 1))
        		integer i, j;
					for (j=0; j<16; j=j+1)
						CIPHER_STATE[STAGE][j*4+3 : j*4]  
							<= SBOX_INV	[
											{	//		 				SR_INV										M		  								  who's missing  M1 or M0
												(
												((CIPHER_STATE[STAGE-1][(j[3:2]*16 + 3)%64] ^ RC[STAGE][(j[3:2]*16 + 3)%64] ^ K1[(j[3:2]*16 + 3)%64]) && MISS[(j[1:0]*4+3 +(j[2]^j[3])*4)%16][0]) ^ 
												((CIPHER_STATE[STAGE-1][(j[3:2]*16 +55)%64] ^ RC[STAGE][(j[3:2]*16 +55)%64] ^ K1[(j[3:2]*16 +55)%64]) && MISS[(j[1:0]*4+3 +(j[2]^j[3])*4)%16][1]) ^
												((CIPHER_STATE[STAGE-1][(j[3:2]*16 +43)%64] ^ RC[STAGE][(j[3:2]*16 +43)%64] ^ K1[(j[3:2]*16 +43)%64]) && MISS[(j[1:0]*4+3 +(j[2]^j[3])*4)%16][2]) ^ 
												((CIPHER_STATE[STAGE-1][(j[3:2]*16 +31)%64] ^ RC[STAGE][(j[3:2]*16 +31)%64] ^ K1[(j[3:2]*16 +31)%64]) && MISS[(j[1:0]*4+3 +(j[2]^j[3])*4)%16][3]) 	 
												),

												(
												((CIPHER_STATE[STAGE-1][(j[3:2]*16 + 2)%64] ^ RC[STAGE][(j[3:2]*16 + 2)%64] ^ K1[(j[3:2]*16 + 2)%64]) && MISS[(j[1:0]*4+2 +(j[2]^j[3])*4)%16][0]) ^ 
												((CIPHER_STATE[STAGE-1][(j[3:2]*16 +54)%64] ^ RC[STAGE][(j[3:2]*16 +54)%64] ^ K1[(j[3:2]*16 +54)%64]) && MISS[(j[1:0]*4+2 +(j[2]^j[3])*4)%16][1]) ^
												((CIPHER_STATE[STAGE-1][(j[3:2]*16 +42)%64] ^ RC[STAGE][(j[3:2]*16 +42)%64] ^ K1[(j[3:2]*16 +42)%64]) && MISS[(j[1:0]*4+2 +(j[2]^j[3])*4)%16][2]) ^ 
												((CIPHER_STATE[STAGE-1][(j[3:2]*16 +30)%64] ^ RC[STAGE][(j[3:2]*16 +30)%64] ^ K1[(j[3:2]*16 +30)%64]) && MISS[(j[1:0]*4+2 +(j[2]^j[3])*4)%16][3]) 	 
												),

												(
												((CIPHER_STATE[STAGE-1][(j[3:2]*16 + 1)%64] ^ RC[STAGE][(j[3:2]*16 + 1)%64] ^ K1[(j[3:2]*16 + 1)%64]) && MISS[(j[1:0]*4+1 +(j[2]^j[3])*4)%16][0]) ^ 
												((CIPHER_STATE[STAGE-1][(j[3:2]*16 +53)%64] ^ RC[STAGE][(j[3:2]*16 +53)%64] ^ K1[(j[3:2]*16 +53)%64]) && MISS[(j[1:0]*4+1 +(j[2]^j[3])*4)%16][1]) ^
												((CIPHER_STATE[STAGE-1][(j[3:2]*16 +41)%64] ^ RC[STAGE][(j[3:2]*16 +41)%64] ^ K1[(j[3:2]*16 +41)%64]) && MISS[(j[1:0]*4+1 +(j[2]^j[3])*4)%16][2]) ^ 
												((CIPHER_STATE[STAGE-1][(j[3:2]*16 +29)%64] ^ RC[STAGE][(j[3:2]*16 +29)%64] ^ K1[(j[3:2]*16 +29)%64]) && MISS[(j[1:0]*4+1 +(j[2]^j[3])*4)%16][3]) 
												),	 

												(
												((CIPHER_STATE[STAGE-1][(j[3:2]*16 + 0)%64] ^ RC[STAGE][(j[3:2]*16 + 0)%64] ^ K1[(j[3:2]*16 + 0)%64]) && MISS[(j[1:0]*4+0 +(j[2]^j[3])*4)%16][0]) ^ 
											    ((CIPHER_STATE[STAGE-1][(j[3:2]*16 +52)%64] ^ RC[STAGE][(j[3:2]*16 +52)%64] ^ K1[(j[3:2]*16 +52)%64]) && MISS[(j[1:0]*4+0 +(j[2]^j[3])*4)%16][1]) ^ 
												((CIPHER_STATE[STAGE-1][(j[3:2]*16 +40)%64] ^ RC[STAGE][(j[3:2]*16 +40)%64] ^ K1[(j[3:2]*16 +40)%64]) && MISS[(j[1:0]*4+0 +(j[2]^j[3])*4)%16][2]) ^ 
												((CIPHER_STATE[STAGE-1][(j[3:2]*16 +28)%64] ^ RC[STAGE][(j[3:2]*16 +28)%64] ^ K1[(j[3:2]*16 +28)%64]) && MISS[(j[1:0]*4+0 +(j[2]^j[3])*4)%16][3])
												)
											}
										]

 
				end // -------- Reverse stages -------- 	 
			end // if PRINCE_ON


            else // if not PRINCE_EN
            begin
            	CIPHER_STATE[STAGE] <= 0;
            end 
            
        end // always
    end // generate for
endgenerate



// --------------------------------------------------------------
endmodule



/*
--- Forward Stages ---

            			Ri, i <= 5:     S -> M -> ^ RCi ^ K1

            			// 16 SBOXes
            			SBOX[KEY_WHITEN[3： 0]],		// 0
            			SBOX[KEY_WHITEN[7： 4]],		// 1
            			SBOX[KEY_WHITEN[11：8]],		// 2
            			SBOX[KEY_WHITEN[15：12]],	// 3
            			SBOX[KEY_WHITEN[19：16]],	// 4
            			SBOX[KEY_WHITEN[23：20]],	// 5
            			SBOX[KEY_WHITEN[27：24]],	// 6
            			SBOX[KEY_WHITEN[31：28]],	// 7
            			SBOX[KEY_WHITEN[35：32]],	// 8
						SBOX[KEY_WHITEN[39：36]],	// 9
						SBOX[KEY_WHITEN[43：40]],	// A
						SBOX[KEY_WHITEN[47：44]],	// B
						SBOX[KEY_WHITEN[51：48]],	// C
						SBOX[KEY_WHITEN[55：52]],	// D
						SBOX[KEY_WHITEN[59：56]],	// E
						SBOX[KEY_WHITEN[63：60]],	// F
						

						// Shift Row (SR)
						//	SR: 		0 1 2 3 4 5 6 7 8 9 A B C D E F 
						//			 -> 0 5 A F 4 9 E 3 8 D 2 7 C 1 6 B
													   ori  new
						SBOX[KEY_WHITEN[3 ： 0]],	// 0	0
						SBOX[KEY_WHITEN[23：20]],	// 5	1
						SBOX[KEY_WHITEN[43：40]],	// A 	2
						SBOX[KEY_WHITEN[63：60]],	// F 	3

						SBOX[KEY_WHITEN[19：16]],	// 4 	4
						SBOX[KEY_WHITEN[39：36]],	// 9 	5
						SBOX[KEY_WHITEN[59：56]],	// E 	6
						SBOX[KEY_WHITEN[15：12]],	// 3 	7

						SBOX[KEY_WHITEN[35：32]],	// 8 	8
						SBOX[KEY_WHITEN[55：52]],	// D 	9
						SBOX[KEY_WHITEN[11： 8]],	// 2 	A
						SBOX[KEY_WHITEN[31：28]],	// 7 	B

						SBOX[KEY_WHITEN[51：48]],	// C 	C
						SBOX[KEY_WHITEN[7 ： 4]],	// 1 	D
						SBOX[KEY_WHITEN[27：24]],	// 6 	E
						SBOX[KEY_WHITEN[47：44]],	// B 	F
						

						// M'
						// Rows that consists m0, m1, m2, m3
						parameter [3:0] m_row [0:3] = {	
									4'b0111,
									4'b1011,
									4'b1101,
									4'b1110
								};

						parameter [3:0] MISS [0:15] = {
														4'h0, 4'h1, 4'h2, 4'h3,
														4'h3, 4'h0, 4'h1, 4'h2,
														4'h2, 4'h3, 4'h0, 4'h1,
														4'h1, 4'h2, 4'h3, 4'h0
													}



						Equation																								#bit 	in	missing
						// ---------------- 1st 16 bits with M0 ----------------
						M_out[0]  = SBOX[KEY_WHITEN[23：20]][0] ^ SBOX[KEY_WHITEN[43：40]][0] ^ SBOX[KEY_WHITEN[63：60]][0]		\\ 0 	123	0
						M_out[1]  = SBOX[KEY_WHITEN[3 ： 0]][1] ^ SBOX[KEY_WHITEN[43：40]][1] ^ SBOX[KEY_WHITEN[63：60]][1]		\\ 1	023	1
						M_out[2]  = SBOX[KEY_WHITEN[3 ： 0]][2] ^ SBOX[KEY_WHITEN[23：20]][2] ^ SBOX[KEY_WHITEN[63：60]][2]		\\ 2	013	2
						M_out[3]  = SBOX[KEY_WHITEN[3 ： 0]][3] ^ SBOX[KEY_WHITEN[23：20]][3] ^ SBOX[KEY_WHITEN[43：40]][3]		\\ 3	012	3

						M_out[4]  = SBOX[KEY_WHITEN[3 ： 0]][0] ^ SBOX[KEY_WHITEN[23：20]][0] ^ SBOX[KEY_WHITEN[43：40]][0]		\\ 4	012	3
					    M_out[5]  = SBOX[KEY_WHITEN[23：20]][1] ^ SBOX[KEY_WHITEN[43：40]][1] ^ SBOX[KEY_WHITEN[63：60]][1]		\\ 5	123	0
					    M_out[6]  = SBOX[KEY_WHITEN[3 ： 0]][2] ^ SBOX[KEY_WHITEN[43：40]][2] ^ SBOX[KEY_WHITEN[63：60]][2]		\\ 6	023	1
					    M_out[7]  = SBOX[KEY_WHITEN[3 ： 0]][3] ^ SBOX[KEY_WHITEN[23：20]][3] ^ SBOX[KEY_WHITEN[63：60]][3]		\\ 7	013	2

						M_out[8]  = SBOX[KEY_WHITEN[3 ： 0]][0] ^ SBOX[KEY_WHITEN[23：20]][0] ^ SBOX[KEY_WHITEN[63：60]][0]		\\ 8	013	2
						M_out[9]  = SBOX[KEY_WHITEN[3 ： 0]][1] ^ SBOX[KEY_WHITEN[23：20]][1] ^ SBOX[KEY_WHITEN[43：40]][1]		\\ 9	012	3
						M_out[10] = SBOX[KEY_WHITEN[23：20]][2] ^ SBOX[KEY_WHITEN[43：40]][2] ^ SBOX[KEY_WHITEN[63：60]][2]		\\ 10	123	0
						M_out[11] = SBOX[KEY_WHITEN[3 ： 0]][3] ^ SBOX[KEY_WHITEN[43：40]][3] ^ SBOX[KEY_WHITEN[63：60]][3]		\\ 11	023	1

						M_out[12] = SBOX[KEY_WHITEN[3 ： 0]][0] ^ SBOX[KEY_WHITEN[43：40]][0] ^ SBOX[KEY_WHITEN[63：60]][0]		\\ 12	023	1
						M_out[13] = SBOX[KEY_WHITEN[3 ： 0]][1] ^ SBOX[KEY_WHITEN[23：20]][1] ^ SBOX[KEY_WHITEN[63：60]][1]		\\ 13	013	2
						M_out[14] = SBOX[KEY_WHITEN[3 ： 0]][2] ^ SBOX[KEY_WHITEN[23：20]][2] ^ SBOX[KEY_WHITEN[43：40]][2]		\\ 14	012	3
						M_out[15] = SBOX[KEY_WHITEN[23：20]][3] ^ SBOX[KEY_WHITEN[43：40]][3] ^ SBOX[KEY_WHITEN[63：60]][3]		\\ 15	123	0


						// ---------------- 2nd 16 bits with M1 ----------------
						M_out[16] = SBOX[KEY_WHITEN[19：16]][0] ^ SBOX[KEY_WHITEN[39：36]][0] ^ SBOX[KEY_WHITEN[59：56]][0]		\\ 16	012	3	
						M_out[17] = SBOX[KEY_WHITEN[39：36]][1] ^ SBOX[KEY_WHITEN[59：56]][1] ^ SBOX[KEY_WHITEN[15：12]][1]		\\ 17	123	0
						M_out[18] = SBOX[KEY_WHITEN[19：16]][2] ^ SBOX[KEY_WHITEN[59：56]][2] ^ SBOX[KEY_WHITEN[15：12]][2]		\\ 18	023	1
						M_out[19] = SBOX[KEY_WHITEN[19：16]][3] ^ SBOX[KEY_WHITEN[39：36]][3] ^ SBOX[KEY_WHITEN[15：12]][3]		\\ 19	013	2
		
						M_out[20] = SBOX[KEY_WHITEN[19：16]][0] ^ SBOX[KEY_WHITEN[39：36]][0] ^ SBOX[KEY_WHITEN[15：12]][0]		\\ 20	013	2
						M_out[21] = SBOX[KEY_WHITEN[19：16]][1] ^ SBOX[KEY_WHITEN[39：36]][1] ^ SBOX[KEY_WHITEN[59：56]][1]		\\ 21	012	3
						M_out[22] = SBOX[KEY_WHITEN[39：36]][2] ^ SBOX[KEY_WHITEN[59：56]][2] ^ SBOX[KEY_WHITEN[15：12]][2]		\\ 22	123	0
						M_out[23] = SBOX[KEY_WHITEN[19：16]][3] ^ SBOX[KEY_WHITEN[59：56]][3] ^ SBOX[KEY_WHITEN[15：12]][3]		\\ 23	023	1

						M_out[24] = SBOX[KEY_WHITEN[19：16]][0] ^ SBOX[KEY_WHITEN[59：56]][0] ^ SBOX[KEY_WHITEN[15：12]][0]		\\ 24	023	1
						M_out[25] = SBOX[KEY_WHITEN[19：16]][1] ^ SBOX[KEY_WHITEN[39：36]][1] ^ SBOX[KEY_WHITEN[15：12]][1]		\\ 25	013	2
						M_out[26] = SBOX[KEY_WHITEN[19：16]][2] ^ SBOX[KEY_WHITEN[39：36]][2] ^ SBOX[KEY_WHITEN[59：56]][2]		\\ 26	012	3
						M_out[27] = SBOX[KEY_WHITEN[39：36]][3] ^ SBOX[KEY_WHITEN[59：56]][3] ^ SBOX[KEY_WHITEN[15：12]][3]		\\ 27	123	0

						M_out[28] = SBOX[KEY_WHITEN[39：36]][0] ^ SBOX[KEY_WHITEN[59：56]][0] ^ SBOX[KEY_WHITEN[15：12]][0]		\\ 28	123	0
						M_out[29] = SBOX[KEY_WHITEN[19：16]][1] ^ SBOX[KEY_WHITEN[59：56]][1] ^ SBOX[KEY_WHITEN[15：12]][1]		\\ 29	023	1
						M_out[30] = SBOX[KEY_WHITEN[19：16]][2] ^ SBOX[KEY_WHITEN[39：36]][2] ^ SBOX[KEY_WHITEN[15：12]][2]		\\ 30	013	2
						M_out[31] = SBOX[KEY_WHITEN[19：16]][3] ^ SBOX[KEY_WHITEN[39：36]][3] ^ SBOX[KEY_WHITEN[59：56]][3]		\\ 31	012	3


						// ---------------- 3rd 16 bits with M1 ----------------
						M_out[32] = SBOX[KEY_WHITEN[35：32]][0] ^ SBOX[KEY_WHITEN[55：52]][0] ^ SBOX[KEY_WHITEN[11： 8]][0]		\\ 32	012	3
						M_out[33] = SBOX[KEY_WHITEN[55：52]][1] ^ SBOX[KEY_WHITEN[11： 8]][1] ^ SBOX[KEY_WHITEN[31：28]][1]		\\ 33	123	0
						M_out[34] = SBOX[KEY_WHITEN[35：32]][2] ^ SBOX[KEY_WHITEN[11： 8]][2] ^ SBOX[KEY_WHITEN[31：28]][2]		\\ 34	023	1
						M_out[35] = SBOX[KEY_WHITEN[35：32]][3] ^ SBOX[KEY_WHITEN[55：52]][3] ^ SBOX[KEY_WHITEN[31：28]][3]		\\ 35	013	2

						M_out[36] = SBOX[KEY_WHITEN[35：32]][0] ^ SBOX[KEY_WHITEN[55：52]][0] ^ SBOX[KEY_WHITEN[31：28]][0]		\\ 36	013	2



						// ---------------- 4th 16 bits with M0 ----------------


						// Stage output
						CIPHER_STATE[STAGE] <= M_out ^ RC[STAGE] ^ K1;
            		*/



// -------- Middle stage -------- 
            	// -> S -> M' -> S_inv 
            	/*
					// 16 SBOXes
        			SBOX[CIPHER_STATE[STAGE-1][3： 0]],		// 0
        			SBOX[CIPHER_STATE[STAGE-1][7： 4]],		// 1
        			SBOX[CIPHER_STATE[STAGE-1][11：8]],		// 2
        			SBOX[CIPHER_STATE[STAGE-1][15：12]],		// 3

        			SBOX[CIPHER_STATE[STAGE-1][19：16]],		// 4
        			SBOX[CIPHER_STATE[STAGE-1][23：20]],		// 5
        			SBOX[CIPHER_STATE[STAGE-1][27：24]],		// 6
        			SBOX[CIPHER_STATE[STAGE-1][31：28]],		// 7

        			SBOX[CIPHER_STATE[STAGE-1][35：32]],		// 8
					SBOX[CIPHER_STATE[STAGE-1][39：36]],		// 9
					SBOX[CIPHER_STATE[STAGE-1][43：40]],		// A
					SBOX[CIPHER_STATE[STAGE-1][47：44]],		// B

					SBOX[CIPHER_STATE[STAGE-1][51：48]],		// C
					SBOX[CIPHER_STATE[STAGE-1][55：52]],		// D
					SBOX[CIPHER_STATE[STAGE-1][59：56]],		// E
					SBOX[CIPHER_STATE[STAGE-1][63：60]],		// F

					// ---------------- 1st 16 bits with M0 ----------------
					M_out[0]  = SBOX[CIPHER_STATE[STAGE-1][7 ： 4]][0] ^ SBOX[CIPHER_STATE[STAGE-1][11：8]][0] ^ SBOX[CIPHER_STATE[STAGE-1][15：12]][0]		\\ 0 	123	0
					M_out[1]  = SBOX[CIPHER_STATE[STAGE-1][3 ： 0]][1] ^ SBOX[CIPHER_STATE[STAGE-1][11：8]][1] ^ SBOX[CIPHER_STATE[STAGE-1][15：12]][1]		\\ 1	023	1
					M_out[2]  = SBOX[CIPHER_STATE[STAGE-1][3 ： 0]][2] ^ SBOX[CIPHER_STATE[STAGE-1][7 ：4]][2] ^ SBOX[CIPHER_STATE[STAGE-1][15：12]][2]		\\ 2	013	2
					M_out[3]  = SBOX[CIPHER_STATE[STAGE-1][3 ： 0]][3] ^ SBOX[CIPHER_STATE[STAGE-1][7 ：4]][3] ^ SBOX[CIPHER_STATE[STAGE-1][11： 8]][3]		\\ 3	012	3
 


            	*/



// -------- Reverse stages -------- 
        		/*
					----- Reverse stages -----
					// Ri, i >= 6:     ^ RCi ^ K1 -> M_inv -> S_inv 

					

				    // Ori input: ^ k1 ^ RCi
        			CIPHER_STATE[STAGE-1][3 ： 0] ^ RC[STAGE][3 ： 0] ^ K1[3 ： 0],		// 0
        			CIPHER_STATE[STAGE-1][7 ： 4] ^ RC[STAGE][7 ： 4] ^ K1[7 ： 4],		// 1
        			CIPHER_STATE[STAGE-1][11： 8] ^ RC[STAGE][11： 8] ^ K1[11： 8],		// 2
        			CIPHER_STATE[STAGE-1][15：12] ^ RC[STAGE][15：12] ^ K1[15：12],		// 3
        			CIPHER_STATE[STAGE-1][19：16] ^ RC[STAGE][19：16] ^ K1[19：16],		// 4
        			CIPHER_STATE[STAGE-1][23：20] ^ RC[STAGE][23：20] ^ K1[23：20],		// 5
        			CIPHER_STATE[STAGE-1][27：24] ^ RC[STAGE][27：24] ^ K1[27：24],		// 6
        			CIPHER_STATE[STAGE-1][31：28] ^ RC[STAGE][31：28] ^ K1[31：28],		// 7
        			CIPHER_STATE[STAGE-1][35：32] ^ RC[STAGE][35：32] ^ K1[35：32],		// 8
					CIPHER_STATE[STAGE-1][39：36] ^ RC[STAGE][39：36] ^ K1[39：36],		// 9
					CIPHER_STATE[STAGE-1][43：40] ^ RC[STAGE][43：40] ^ K1[43：40],		// A
					CIPHER_STATE[STAGE-1][47：44] ^ RC[STAGE][47：44] ^ K1[47：44],		// B
					CIPHER_STATE[STAGE-1][51：48] ^ RC[STAGE][51：48] ^ K1[51：48],		// C
					CIPHER_STATE[STAGE-1][55：52] ^ RC[STAGE][55：52] ^ K1[55：52],		// D
					CIPHER_STATE[STAGE-1][59：56] ^ RC[STAGE][59：56] ^ K1[59：56],		// E
					CIPHER_STATE[STAGE-1][63：60] ^ RC[STAGE][63：60] ^ K1[63：60],		// F

					SR_inv			0 1 2 3 4 5 6 7 8 9 A B C D E F 
								 -> 0 D A 7 4 1 E B 8 5 2 F C 9 6 3
											   	   		   	   							   ori  new
					CIPHER_STATE[STAGE-1][3 ： 0] ^ RC[STAGE][3 ： 0] ^ K1[3 ： 0],		// 0	0
					CIPHER_STATE[STAGE-1][55：52] ^ RC[STAGE][55：52] ^ K1[55：52],		// D	1
					CIPHER_STATE[STAGE-1][43：40] ^ RC[STAGE][43：40] ^ K1[43：40],		// A 	2
					CIPHER_STATE[STAGE-1][31：28] ^ RC[STAGE][31：28] ^ K1[31：28],		// 7 	3

					CIPHER_STATE[STAGE-1][19：16] ^ RC[STAGE][19：16] ^ K1[19：16],		// 4 	4
					CIPHER_STATE[STAGE-1][7 ： 4] ^ RC[STAGE][7 ： 4] ^ K1[7 ： 4],		// 1 	5
					CIPHER_STATE[STAGE-1][59：56] ^ RC[STAGE][59：56] ^ K1[59：56],		// E 	6
					CIPHER_STATE[STAGE-1][47：44] ^ RC[STAGE][47：44] ^ K1[47：44],		// B 	7

					CIPHER_STATE[STAGE-1][35：32] ^ RC[STAGE][35：32] ^ K1[35：32],		// 8 	8
					CIPHER_STATE[STAGE-1][23：20] ^ RC[STAGE][23：20] ^ K1[23：20],		// 5 	9
					CIPHER_STATE[STAGE-1][11： 8] ^ RC[STAGE][11： 8] ^ K1[11： 8],		// 2 	A
					CIPHER_STATE[STAGE-1][63：60] ^ RC[STAGE][63：60] ^ K1[63：60],		// F 	B

					CIPHER_STATE[STAGE-1][51：48] ^ RC[STAGE][51：48] ^ K1[51：48],		// C 	C
					CIPHER_STATE[STAGE-1][39：36] ^ RC[STAGE][39：36] ^ K1[39：36],		// 9 	D
					CIPHER_STATE[STAGE-1][27：24] ^ RC[STAGE][27：24] ^ K1[27：24],		// 6 	E
					CIPHER_STATE[STAGE-1][15：12] ^ RC[STAGE][15：12] ^ K1[15：12],		// 3 	F


					// ---------------- 1st 16 bits with M0 ----------------
																			#bit 		missing
					CIPHER_STATE[STAGE-1][52] ^ RC[STAGE][52] ^ K1[52] ^ 
					CIPHER_STATE[STAGE-1][40] ^ RC[STAGE][40] ^ K1[40] ^ 
					CIPHER_STATE[STAGE-1][28] ^ RC[STAGE][28] ^ K1[28]		\\ 0 	123	0

					CIPHER_STATE[STAGE-1][ 1] ^ RC[STAGE][ 1] ^ K1[ 1] ^ 
					CIPHER_STATE[STAGE-1][41] ^ RC[STAGE][41] ^ K1[41] ^ 
					CIPHER_STATE[STAGE-1][29] ^ RC[STAGE][29] ^ K1[29]		\\ 1 	023	1
					
					CIPHER_STATE[STAGE-1][ 2] ^ RC[STAGE][ 2] ^ K1[ 2] ^ 
					CIPHER_STATE[STAGE-1][42] ^ RC[STAGE][42] ^ K1[42] ^ 
					CIPHER_STATE[STAGE-1][30] ^ RC[STAGE][30] ^ K1[30] 		\\ 2 	013	2
					
					CIPHER_STATE[STAGE-1][ 3] ^ RC[STAGE][ 3] ^ K1[ 3] ^ 
					CIPHER_STATE[STAGE-1][43] ^ RC[STAGE][43] ^ K1[43] ^ 
					CIPHER_STATE[STAGE-1][31] ^ RC[STAGE][31] ^ K1[31] 		\\ 3 	012	3


					---

					CIPHER_STATE[STAGE-1][ 0] ^ RC[STAGE][ 0] ^ K1[ 0] ^ 
					CIPHER_STATE[STAGE-1][52] ^ RC[STAGE][52] ^ K1[52] ^ 
					CIPHER_STATE[STAGE-1][40] ^ RC[STAGE][40] ^ K1[40] 		\\ 4 	012	3

					CIPHER_STATE[STAGE-1][53] ^ RC[STAGE][53] ^ K1[53] ^ 
					CIPHER_STATE[STAGE-1][41] ^ RC[STAGE][41] ^ K1[41] ^ 
					CIPHER_STATE[STAGE-1][29] ^ RC[STAGE][29] ^ K1[29] 		\\ 5 	123	0

 
					// ---------------- SBOX_INV ----------------
					SBOX_INV[
								{
									CIPHER_STATE[STAGE-1][52] ^ RC[STAGE][52] ^ K1[52] ^ 
									CIPHER_STATE[STAGE-1][40] ^ RC[STAGE][40] ^ K1[40] ^ 
									CIPHER_STATE[STAGE-1][28] ^ RC[STAGE][28] ^ K1[28] ,	\\ 0 	123	0

									CIPHER_STATE[STAGE-1][ 1] ^ RC[STAGE][ 1] ^ K1[ 1] ^ 
									CIPHER_STATE[STAGE-1][41] ^ RC[STAGE][41] ^ K1[41] ^ 
									CIPHER_STATE[STAGE-1][29] ^ RC[STAGE][29] ^ K1[29] ,	\\ 1 	023	1

									CIPHER_STATE[STAGE-1][ 2] ^ RC[STAGE][ 2] ^ K1[ 2] ^ 
									CIPHER_STATE[STAGE-1][42] ^ RC[STAGE][42] ^ K1[42] ^ 
									CIPHER_STATE[STAGE-1][30] ^ RC[STAGE][30] ^ K1[30] ,	\\ 2 	013	2

									CIPHER_STATE[STAGE-1][ 3] ^ RC[STAGE][ 3] ^ K1[ 3] ^ 
									CIPHER_STATE[STAGE-1][43] ^ RC[STAGE][43] ^ K1[43] ^ 
									CIPHER_STATE[STAGE-1][31] ^ RC[STAGE][31] ^ K1[31] 		\\ 3 	012	3
								}
							]

					SBOX_INV[
								{
									CIPHER_STATE[STAGE-1][ 0] ^ RC[STAGE][ 0] ^ K1[ 0] ^ 
									CIPHER_STATE[STAGE-1][52] ^ RC[STAGE][52] ^ K1[52] ^ 
									CIPHER_STATE[STAGE-1][40] ^ RC[STAGE][40] ^ K1[40] ,	\\ 4 	012	3

									CIPHER_STATE[STAGE-1][53] ^ RC[STAGE][53] ^ K1[53] ^ 
									CIPHER_STATE[STAGE-1][41] ^ RC[STAGE][41] ^ K1[41] ^ 
									CIPHER_STATE[STAGE-1][29] ^ RC[STAGE][29] ^ K1[29] ,	\\ 5 	123	0



								}			
							]


        		*/
