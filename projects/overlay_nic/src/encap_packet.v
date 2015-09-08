
// encapsulate packet with Ether and IPv4 header (34 byte).
//   src mac : 02:a1:a2:e1:e2:e3
//   dst mac : 02:b1:b2:f1:f2:f3
//   src ip : 10.0.0.1
//   dst ip : 10.0.1.1
//   ipproto ipip, chksum 0, ttl 16, flag 0, tos 0.


`timescale 1ns/1ps

module encap_packet
    #(parameter DATA_WIDTH = 64,
      parameter CTRL_WIDTH = DATA_WIDTH/8,
      parameter IO_QUEUE_STAGE_NUM = `IO_QUEUE_STAGE_NUM
      )

      (// data path interface
       output     [DATA_WIDTH-1:0]           out_data,
       output     [CTRL_WIDTH-1:0]           out_ctrl,
       output                                out_wr,
       input                                 out_rdy,

       input  [DATA_WIDTH-1:0]               in_data,
       input  [CTRL_WIDTH-1:0]               in_ctrl,
       input                                 in_wr,
       output                                in_rdy,

       // misc
       input                                 clk,
       input                                 reset);

   // state parameter
   localparam IN_HDR      = 1;
   localparam IN_OTHRHDR  = 2;
   localparam IN_PADDING1 = 3; // dst_mac 6 + src_mac 2
   localparam IN_PADDING2 = 4; // src_mac 4 + ethertype 2 + iv, ihl 1 + tos 1
   localparam IN_PADDING3 = 5; // totlen 2 + id 2 + flag 2 + ttl 1 + proto 1
   localparam IN_PADDING4 = 6; // chksum 2 + srcip 4 + dstip 2
   localparam IN_PADDING5 = 7; // dstip 2 + tmp_data 6
   localparam IN_PACKET   = 8;
   localparam IN_AMARI    = 9;
   

   // wires/regs
   wire [CTRL_WIDTH-1:0] 		     in_ctrl_mod;
   wire [DATA_WIDTH-1:0] 		     in_data_mod;
   reg [CTRL_WIDTH-1:0] 		     out_ctrl_int;
   reg [DATA_WIDTH-1:0] 		     out_data_int;

   reg [DATA_WIDTH-1:0] 		     tmp_data, tmp_data_nxt;

   reg [DATA_WIDTH-1:0] 		     amari_data;
   reg [CTRL_WIDTH-1:0] 		     amari_ctrl;

   reg [3:0] 				     state, state_nxt;

   reg [15:0] 				     new_byte_len;
   reg [15:0] 				     new_word_len;

   reg 					     out_wr_int;
   reg 					     in_fifo_rd_en;
   wire 				     im_fifo_nearly_full;
   wire 				     in_fifo_empty;
   
   
   `CEILDIV_FUNC 

   function integer log2;
      input integer 			     number;
      begin
	 log2=0;
	 while(2**log2<number) begin
	    log2=log2+1;
	 end
      end
   endfunction // log2

   
   // input fifo module
   fallthrough_small_fifo 
     # (.WIDTH (CTRL_WIDTH + DATA_WIDTH), .MAX_DEPTH_BITS (4))
   padding_input_fifo
     (
      .din         ({in_ctrl, in_data}), // data in
      .wr_en       (in_wr),
      .rd_en       (in_fifo_rd_en),
      .dout        ({in_ctrl_mod, in_data_mod}),
      .full        (),
      .prog_full   (),
      .nearly_full (in_fifo_nearly_full),
      .empty       (in_fifo_empty),
      .reset       (reset),
      .clk         (clk)
      );


   // logic
   assign in_rdy = !in_fifo_nearly_full;
   assign out_wr = out_wr_int;
   assign out_data = out_data_int;
   assign out_ctrl = out_ctrl_int;
   
   always @(*) begin

      state_nxt = state;
      tmp_data_nxt = tmp_data;

      out_wr_int = 1'b0;
      in_fifo_rd_en = 1'b0;

      out_ctrl_int = in_ctrl_mod;

      case (state)
	IN_HDR : begin
	   if (!in_fifo_empty && out_rdy) begin

	      out_wr_int = 1'b1;
	      in_fifo_rd_en = 1'b1;

	      if (in_ctrl_mod == IO_QUEUE_STAGE_NUM) begin
		 new_byte_len = in_data_mod[`IOQ_BYTE_LEN_POS+15:`IOQ_BYTE_LEN_POS] + 34;
		 new_word_len = ceildiv (new_byte_len, 8);
		 out_data_int[`IOQ_BYTE_LEN_POS+15:`IOQ_BYTE_LEN_POS] = new_byte_len;
		 out_data_int[`IOQ_WORD_LEN_POS+15:`IOQ_WORD_LEN_POS] = new_word_len;
		 state_nxt = IN_OTHRHDR;
	      end
	   end
	end

	IN_OTHRHDR : begin
	   if (!in_fifo_empty && out_rdy) begin

	      out_wr_int = 1'b1;
	      in_fifo_rd_en = 1'b1;

	      if (in_ctrl_mod != 0) begin
		 out_data_int = in_data_mod; // other header.
	      end else begin
		 // payloda data. stop new data from fifo, and start padding.
		 out_wr_int = 1'b0;
		 in_fifo_rd_en = 1'b0;
		 state_nxt = IN_PADDING1;
	      end
	   end
	end


	IN_PADDING1 : begin
	   // dst_mac 6 + src_mac 2
	   if (out_rdy) begin
	      out_wr_int = 1'b1;
	      out_ctrl_int = 8'd0;
	      out_data_int = { 48'h02A1A2_E1E2E3, 16'h02B1 };
	      state_nxt = IN_PADDING2;
	   end
	end
	
	IN_PADDING2 : begin
	   // src_mac 4 + ethertype 2 + iv, ihl 1 + tos 1
	   if (out_rdy) begin
	      out_wr_int = 1'b1;
	      out_ctrl_int = 8'd0;
	      out_data_int = { 32'hB2_F1F2F3, 16'h0800, 8'h45, 8'h00 };
	      state_nxt = IN_PADDING3;
	   end
	end

	IN_PADDING3 : begin
	   // totlen 2 + id 2 + flag 2 + ttl 1 + proto 1
	   if (out_rdy) begin
	      out_wr_int = 1'b1;
	      out_ctrl_int = 8'd0;
	      // inner ip len is new_byte_len - ether header len
	      out_data_int = { new_byte_len - 14, 16'h00, 16'h00, 8'd16, 8'd4 };
	      state_nxt = IN_PADDING4;
	   end
	end

	IN_PADDING4 : begin
	   // chksum 2 + srcip 4 + dstip 2
	   if (out_rdy) begin
	      out_wr_int = 1'b1;
	      out_ctrl_int = 8'd0;
	      out_data_int = { 16'd0, 32'h0A_00_00_01, 16'h0A_00 };
	      state_nxt = IN_PADDING5;
	   end
	end

	IN_PADDING5 : begin
	   // dst 2, 6 byte tmp_data
	   if (!in_fifo_empty && out_rdy) begin

	      out_wr_int = 1'b1;
	      in_fifo_rd_en = 1'b1;

	      out_ctrl_int = 8'd0;
	      out_data_int = { 16'h01_01, in_data_mod[63:16] };

	      tmp_data_nxt = in_data_mod;
	      state_nxt = IN_PACKET;
	   end
	end

	IN_PACKET : begin
	   
	   if (!in_fifo_empty && out_rdy) begin

	      out_wr_int = 1'b1;
	      in_fifo_rd_en = 1'b1;

	      case (in_ctrl_mod)
		'h00 : begin
		   // a word in the packet.
		   out_data_int = { tmp_data[15:0], in_data_mod[63:16] };
		   tmp_data_nxt = in_data_mod;
		   state_nxt = IN_PACKET;
		end


		// the last word of the frame
		'b10000000 : begin
		   out_data_int = { tmp_data[15:0], in_data_mod[63:56], 40'd0 };
		   out_ctrl_int = 8'b00100000; // 2 + 1 = 3 byte
		   state_nxt = IN_HDR;
		end
		
		'b01000000 : begin
		   out_data_int = { tmp_data[15:0], in_data_mod[63:48], 32'd0  };
		   out_ctrl_int = 8'b00010000; // 2 + 2 = 4 byte
		   state_nxt = IN_HDR;
		end

		'b00100000 : begin
		   out_data_int = { tmp_data[15:0], in_data_mod[63:40], 24'd0 };
		   out_ctrl_int = 8'b00001000; // 2 + 3 = 5 byte
		   state_nxt = IN_HDR;
		end

		'b00010000 : begin
		   out_data_int = { tmp_data[15:0], in_data_mod[63:32], 16'd0 };
		   out_ctrl_int = 8'b00000100; // 2 + 4 = 6 byte
		   state_nxt = IN_HDR;
		end

		'b00001000 : begin
		   out_data_int = { tmp_data[15:0], in_data_mod[63:24], 8'd0 };
		   out_ctrl_int = 8'b00000010; // 2 + 5 = 7 byte
		   state_nxt = IN_HDR;
		end

		'b00000100 : begin
		   out_data_int = { tmp_data[15:0], in_data_mod[63:16] };
		   out_ctrl_int = 8'b00000001; // 2 + 6 = 8 byte
		   state_nxt = IN_HDR;
		end

		// Amaru case
		'b00000010 : begin
		   out_data_int = { tmp_data[15:0], in_data_mod[63:16] };
		   out_ctrl_int = 8'h00;
		   amari_ctrl = 'b10000000; // amari 1 byte
		   amari_data = { in_data_mod[15:8], 56'd0 };
		   state_nxt = IN_AMARI;
		end

		'b00000001 : begin
		   out_data_int = { tmp_data[15:0], in_data_mod[63:16] };
		   out_ctrl_int = 8'h00;
		   amari_ctrl = 'b01000000; // amari 1 byte
		   amari_data = { in_data_mod[15:0], 48'd0 };
		   state_nxt = IN_AMARI;
		end
	      endcase
	   end
	end

	IN_AMARI: begin
	   if (out_rdy) begin
	      out_wr_int = 1'b1;
	      out_data_int = amari_data;
	      out_ctrl_int = amari_ctrl;
	      state_nxt = IN_HDR;
	   end
	end

      endcase
   end
   

   
   always @(posedge clk) begin
      if (reset) begin
	 state <= IN_HDR;
	 tmp_data <= 0;
      end
      else begin
	 state <= state_nxt;
	 tmp_data <= tmp_data_nxt;
      end
   end



   /* registers unused */
   /*
   always @(posedge clk) begin
      reg_req_out        <= reg_req_in;
      reg_ack_out        <= reg_ack_in;
      reg_rd_wr_L_out    <= reg_rd_wr_L_in;
      reg_addr_out       <= reg_addr_in;
      reg_data_out       <= reg_data_in;
      reg_src_out        <= reg_src_in;
   end */
   

endmodule
	 