module bitcoin_hash (input logic        clk, reset_n, start,
                     input logic [15:0] message_addr, output_addr,
                    output logic        done, mem_clk, mem_we,
                    output logic [15:0] mem_addr,
                    output logic [31:0] mem_write_data,
                     input logic [31:0] mem_read_data);

parameter num_nonces = 16;
parameter NUM_OF_WORDS = 20;

logic [31:0] hout[num_nonces];

parameter int k[64] = '{
    32'h428a2f98,32'h71374491,32'hb5c0fbcf,32'he9b5dba5,32'h3956c25b,32'h59f111f1,32'h923f82a4,32'hab1c5ed5,
    32'hd807aa98,32'h12835b01,32'h243185be,32'h550c7dc3,32'h72be5d74,32'h80deb1fe,32'h9bdc06a7,32'hc19bf174,
    32'he49b69c1,32'hefbe4786,32'h0fc19dc6,32'h240ca1cc,32'h2de92c6f,32'h4a7484aa,32'h5cb0a9dc,32'h76f988da,
    32'h983e5152,32'ha831c66d,32'hb00327c8,32'hbf597fc7,32'hc6e00bf3,32'hd5a79147,32'h06ca6351,32'h14292967,
    32'h27b70a85,32'h2e1b2138,32'h4d2c6dfc,32'h53380d13,32'h650a7354,32'h766a0abb,32'h81c2c92e,32'h92722c85,
    32'ha2bfe8a1,32'ha81a664b,32'hc24b8b70,32'hc76c51a3,32'hd192e819,32'hd6990624,32'hf40e3585,32'h106aa070,
    32'h19a4c116,32'h1e376c08,32'h2748774c,32'h34b0bcb5,32'h391c0cb3,32'h4ed8aa4a,32'h5b9cca4f,32'h682e6ff3,
    32'h748f82ee,32'h78a5636f,32'h84c87814,32'h8cc70208,32'h90befffa,32'ha4506ceb,32'hbef9a3f7,32'hc67178f2
};

// Student to add rest of the code here

// FSM state variables 
enum logic [4:0] {IDLE, READ, BLOCK1, COMPUTE1, BLOCK2, COMPUTE2, BLOCK3, COMPUTE3, WRITE} state;

// declare such unpacked arrays for a thru h
logic [31:0] h0[num_nonces], h1[num_nonces], h2[num_nonces], h3[num_nonces], h4[num_nonces], h5[num_nonces], h6[num_nonces], h7[num_nonces];
logic [31:0] a[num_nonces], b[num_nonces], c[num_nonces], d[num_nonces], e[num_nonces], f[num_nonces], g[num_nonces], h[num_nonces];

// Local variables
logic [31:0] w[64];
logic [31:0] message[20];
logic [31:0] wt;
logic [ 7:0] i, j;
logic [15:0] offset; // in word address
logic [ 7:0] num_blocks;
logic        cur_we;
logic [15:0] cur_addr;
logic [31:0] cur_write_data;
logic [512:0] memory_block;
logic [ 7:0] tstep;

// local variables
logic [1:0] current_block;

assign num_blocks = determine_num_blocks(NUM_OF_WORDS); 

// Function to determine number of blocks in memory to fetch
function logic [15:0] determine_num_blocks(input logic [31:0] size);

  // dont hardcode the value "2" 
  logic [15:0] blocks;
  if (((size * 32) % 512) != 0) begin
    blocks = ((size * 32) / 512); // if 640, blocks = 1
    determine_num_blocks = blocks + 1; // then blocks = 2 (desired number)
  end

  else begin
    blocks = ((size * 32) / 512); // if 640, blocks = 1
    determine_num_blocks = blocks;
  end

endfunction

// word expansion function
function logic [31:0] word_expansion(logic[7:0] t);
  logic [31:0] s1, s0;
  s0 = rightrotate(w[t-15], 7) ^ rightrotate(w[t-15], 18) ^ (w[t-15] >> 3);
  s1 = rightrotate(w[t-2], 17) ^ rightrotate(w[t-2], 19) ^ (w[t-2] >> 10);
  word_expansion = w[t-16] + s0 + w[t-7] + s1;
endfunction

// SHA256 hash round
// code from slides
function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, h, w,
                                 input logic [7:0] t);
    logic [31:0] S1, S0, ch, maj, t1, t2; // internal signals
  begin

    S0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate (a, 22);
    maj = (a & b) ^ (a & c) ^ (b & c);
    t2 = S0 + maj;
    S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
    ch = (e & f) ^ ((~ e) & g);
    t1 = h + S1 + ch + k[t] + w;
    sha256_op = {t1 + t2, a, b, c, d + t1, e, f, g};

  end
endfunction


// Generate request to memory
// for reading from memory to get original message
// for writing final computed has value
assign mem_clk = clk;
assign mem_addr = cur_addr + offset;
assign mem_we = cur_we;
assign mem_write_data = cur_write_data;

// Right Rotation Example : right rotate input x by r
// Lets say input x = 1111 ffff 2222 3333 4444 6666 7777 8888
// lets say r = 4
// x >> r  will result in : 0000 1111 ffff 2222 3333 4444 6666 7777 
// x << (32-r) will result in : 8888 0000 0000 0000 0000 0000 0000 0000
// final right rotate expression is = (x >> r) | (x << (32-r));
// (0000 1111 ffff 2222 3333 4444 6666 7777) | (8888 0000 0000 0000 0000 0000 0000 0000)
// final value after right rotate = 8888 1111 ffff 2222 3333 4444 6666 7777
// Right rotation function
function logic [31:0] rightrotate(input logic [31:0] x,
                                  input logic [ 7:0] r);
   rightrotate = (x >> r) | (x << (32 - r));
endfunction


// SHA-256 FSM 
// Get a BLOCK from the memory, COMPUTE Hash output using SHA256 function
// and write back hash value back to memory
always_ff @(posedge clk, negedge reset_n) begin
  if (!reset_n) begin
    cur_we <= 1'b0;
    state <= IDLE;
  end 
  else begin
	case (state)
    // Initialize hash values h0 to h7 and a to h, other variables and memory we, address offset, etc
		IDLE: begin 
			if(start) begin
				// initial hash values
				h0[0] <= 32'h6a09e667;
				h1[0] <= 32'hbb67ae85;
				h2[0] <= 32'h3c6ef372;
				h3[0] <= 32'ha54ff53a;
				h4[0] <= 32'h510e527f;
				h5[0] <= 32'h9b05688c;
				h6[0] <= 32'h1f83d9ab;
				h7[0] <= 32'h5be0cd19;

				a[0] <= 32'h6a09e667;
				b[0] <= 32'hbb67ae85;
				c[0] <= 32'h3c6ef372;
				d[0] <= 32'ha54ff53a;
				e[0] <= 32'h510e527f;
				f[0] <= 32'h9b05688c;
				g[0] <= 32'h1f83d9ab;
				h[0] <= 32'h5be0cd19;

				// assign and initialize variables
				current_block <= 0;
				offset <= 0; 
				cur_addr <= message_addr;
				cur_we <= 1'b0;
				cur_write_data <= 32'h0;
				i <= 0;
				j <= 0;
				state <= READ;
			end

			else state <= IDLE;
		end

		
		READ: begin
			// https://piazza.com/class/kxt74scerj075n?cid=427
			if(offset <= 19) begin  

				if (offset == 0) begin 
					offset <= offset + 1;
					state <= READ;
				end
	
				else begin
					// Read message word from testbench memory and store it in message array in chunks of 32 bits
					// mem_read_data will have 32 bits of message word which is coming from dpsram memory in testbench
					// using "offset" index variable, store 32-bit message word in each "message" array location.    
					message[offset - 1] <= mem_read_data;
					// Increment memory address to fetch next block 
					offset <= offset + 1;
					// continue to set mem_we = 0 to read memory until all 20 words are read
					cur_we <= 1'b0; 
					state <= READ;
				end
			end

			else begin
				// realign for mem_addr continuous assignment
				offset <= 0;
				state <= BLOCK1;
			end
		end
		

		BLOCK1: begin

 			// create block and move to COMPUTE 1
			for (int t = 0; t < 16; t++) begin
				w[t] <= message[t];
			end
			state <= COMPUTE1;
		
		end
		

		COMPUTE1: begin

 			// word expansion and perform sha_op similar to what you have today for part-1 simplified sha256 as for block-1, this code is similar to what you have for block1 in simplified sha256
			// 64 processing rounds steps for 512-bit block 
			if (i <= 64) begin
				if (i < 16) begin
					{a[0],b[0],c[0],d[0],e[0],f[0],g[0],h[0]} <= sha256_op(a[0], b[0], c[0], d[0], e[0], f[0], g[0], h[0], w[i], i);
				end

				else begin
						w[i] <= word_expansion(i);
						if(i != 16) {a[0],b[0],c[0],d[0],e[0],f[0],g[0],h[0]} <= sha256_op(a[0], b[0], c[0], d[0], e[0], f[0], g[0], h[0], w[i-1], i-1);
						// don't do anything on 16th iteration as w[16] word is not available yet so do sha_op for w[16] on 17th cycle/iteration. sha_op for w[17] is done on 18th cycle iteration and so one. 
				end

				// increment then compute
				i <= i + 1;
				state <= COMPUTE1;

			end

			else begin 
				// increment block #
				current_block <= current_block + 1;

				// update current hash with new hash values
				h0[0] <= h0[0] + a[0];
				h1[0] <= h1[0] + b[0];
				h2[0] <= h2[0] + c[0];
				h3[0] <= h3[0] + d[0];
				h4[0] <= h4[0] + e[0];
				h5[0] <= h5[0] + f[0];
				h6[0] <= h6[0] + g[0];
				h7[0] <= h7[0] + h[0];

				state <= BLOCK2;
				i <= 0;
			end

		end

		
		BLOCK2: begin
			
			// last 3 words in memory
			for (int t = 0; t < 3; t++) begin
				w[t] <= message[t+16];
			end

			// add 1 delimiter after msg
			w[4] <= 32'h80000000;

			// 0 padding
			for (int m = 5; m < 15; m++) begin
				w[m] <= 32'h00000000;
			end
      
			// size
			w[15] <= 32'd640;
			
			// create block 2 and prepare a through h hashes,  which is now assigned hash h0 to h7 from first block
			for (int n = 1; n < num_nonces; n++) begin
				h0[n] <= h0[0];
				h1[n] <= h1[0];
				h2[n] <= h2[0];
				h3[n] <= h3[0];
				h4[n] <= h4[0];
				h5[n] <= h5[0];
				h6[n] <= h6[0];
				h7[n] <= h7[0];
				
				// re-initialize a-h with h0-h7 values before compute
				a[n] <= h0[0];
				b[n] <= h1[0];
				c[n] <= h2[0];
				d[n] <= h3[0];
				e[n] <= h4[0];
				f[n] <= h5[0];
				g[n] <= h6[0];
				h[n] <= h7[0];
			end
			
			// then move to COMPUTE2
			state <= COMPUTE2;

		end

		
		COMPUTE2: begin

 			// Iterate 16 times for each nonce

			for (int n = 0; n < num_nonces; n++)begin
 				if(i < 64) begin
  				if (i < 16) begin
						wt <= (i == 3) ? n : w[i]; 
 						{a[n],b[n],c[n],d[n],e[n],f[n],g[n],h[n]} <= sha256_op(a[n], b[n], c[n], d[n], e[n], f[n], g[n], h[n], wt, i);
  				end
  				else begin
     				w[i] <= word_expansion(i);
						if(i != 16) {a[n],b[n],c[n],d[n],e[n],f[n],g[n],h[n]} <= sha256_op(a[n], b[n], c[n], d[n], e[n], f[n], g[n], h[n], w[i-1], i-1);
  				end
					i <= i + 1;
					state <= COMPUTE2;
				end

  			else begin
          h0[n] <= h0[n] + a[n];
          h1[n] <= h1[n] + b[n];
          h2[n] <= h2[n] + c[n];
          h3[n] <= h3[n] + d[n];
          h4[n] <= h4[n] + e[n];
          h5[n] <= h5[n] + f[n];
          h6[n] <= h6[n] + g[n];
          h7[n] <= h7[n] + h[n];

          state <= BLOCK3;
          i <= 0;
  			end
			end
			
		end

		
		BLOCK3: begin

 			// H0 to H7 from phase 2
			w[0] <= h0[0];
			w[1] <= h1[0];
			w[2] <= h2[0];
			w[3] <= h3[0];
			w[4] <= h4[0];
			w[5] <= h5[0];
			w[6] <= h6[0];
			w[7] <= h7[0];

			// add 1 delimiter after msg
			w[8] <= 32'h80000000;

			// 0 padding
			for (int m = 9; m < 15; m++) begin
				w[m] <= 32'h00000000;
			end
      
			// size
			w[15] <= 32'd256;
			
 			// create block 2 and prepare a through h hashes, which is original h0 to h7
			for (int n = 1; n < num_nonces; n++) begin
				h0[n] <= 32'h6a09e667;
				h1[n] <= 32'hbb67ae85;
				h2[n] <= 32'h3c6ef372;
				h3[n] <= 32'ha54ff53a;
				h4[n] <= 32'h510e527f;
				h5[n] <= 32'h9b05688c;
				h6[n] <= 32'h1f83d9ab;
				h7[n] <= 32'h5be0cd19;
				
				// re-initialize a-h with h0-h7 values before compute
				a[n] <= h0[n];
				b[n] <= h1[n];
				c[n] <= h2[n];
				d[n] <= h3[n];
				e[n] <= h4[n];
				f[n] <= h5[n];
				g[n] <= h6[n];
				h[n] <= h7[n];
			end
			
			// then move to COMPUTE3	 
			state <= COMPUTE3;
			
		end


		COMPUTE3: begin
 			for (int n = 0; n < num_nonces; n++)begin
 				if(i < 64) begin
  				if (i < 16) begin
 						{a[n],b[n],c[n],d[n],e[n],f[n],g[n],h[n]} <= sha256_op(a[n], b[n], c[n], d[n], e[n], f[n], g[n], h[n], w[i], i);
  				end
  				else begin
						w[i] <= word_expansion(i);
						if(i != 16) {a[n],b[n],c[n],d[n],e[n],f[n],g[n],h[n]} <= sha256_op(a[n], b[n], c[n], d[n], e[n], f[n], g[n], h[n], w[i-1], i-1);
  				end
     			i <= i + 1;
  				state <= COMPUTE3;
    		end
    		else begin
					h0[n] <= h0[n] + a[n];		
          h1[n] <= h1[n] + b[n];
					h2[n] <= h2[n] + c[n];
  				h3[n] <= h3[n] + d[n];
					h4[n] <= h4[n] + e[n];
          h5[n] <= h5[n] + f[n];
					h6[n] <= h6[n] + g[n];
    			h7[n] <= h7[n] + h[n];
					
					state <= WRITE;
					i <= 0;
				end
			end
		end


    // h0[n] each are 32 bit hashes, which makes up total 256 bit value
    // write back these h0[n] for n = 0...7 to memory starting from output_addr
    WRITE: begin

      // write enable
      cur_we <= 1'b1;
     
      // from slides
      cur_addr <= output_addr - 1;
      case (offset)

        0: begin
          
          cur_write_data <= h0[0];
          offset <= offset + 1;
          state <= WRITE;
        end

        1: begin
          cur_write_data <= h0[1];
          offset <= offset + 1;
          state <= WRITE;
        end

        2: begin 
          cur_write_data <= h0[2];
          offset <= offset + 1;
          state <= WRITE;
        end

        3: begin
          cur_write_data <= h0[3];
          offset <= offset + 1;
          state <= WRITE;
        end

        4: begin
          cur_write_data <= h0[4];
          offset <= offset + 1;
          state <= WRITE;
        end

        5: begin
          cur_write_data <= h0[5];
          offset <= offset + 1;
          state <= WRITE;
        end

        6: begin
          cur_write_data <= h0[6];
         offset <= offset + 1;
          state <= WRITE;
        end

        7: begin
          cur_write_data <= h0[7];
         offset <= offset + 1;
          state <= WRITE;
        end

        8: begin
          state <= IDLE;
        end 

      endcase

    end

   endcase
 end
end

// Generate done when SHA256 hash computation has finished and moved to IDLE state
assign done = (state == IDLE);

endmodule
