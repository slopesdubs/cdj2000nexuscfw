/* Experimental CDJ-2000NXS PWV5 GUI consumer.
 *
 * Entry ABI matches stock 0x00D2F51C: R0 is the reassembled byte count.
 * The command-32 receiver is redirected to the stock 12-byte record arena at
 * 0x01011940. Conversion runs backwards, expanding two-byte input words into
 * non-overlapping 12-byte records. RGB555 is stored at record +4.
 *
 * This routine is designed for 0x00D4A000 and is not hardware-approved yet.
 */

        .section .text
        .align 4
        .global pwv5_gui_consumer
        .global pwv5_first_copy
        .extern stock_detail_copy

pwv5_gui_consumer:
        LINK 0;
        [--SP] = (R7:4, P5:3);

        /* Publish zero records until the backwards conversion is complete. */
        P4.L = 0x3698;
        P4.H = 0x00CD;
        R6 = 0;
        [P4] = R6;

        /* PWV5 uses exactly two bytes per column; reject malformed odd input. */
        R7 = R0;
        CC = BITTST (R7, 0);
        IF CC JUMP .Ldone;
        R7 >>= 1;
        CC = R7 <= 0;
        IF CC JUMP .Ldone;
        R4 = 0x746C;       /* canonical maximum: 29,804 columns */
        CC = R7 <= R4 (IU);
        IF !CC JUMP .Ldone;

        /* Input ends at base + byte_count; output ends at base + count*12. */
        P2.L = 0x1940;
        P2.H = 0x0101;
        P3 = R7;
        P3 = P3 << 1;
        P2 = P2 + P3;
        P2 += -2;
        P0.L = 0x1940;
        P0.H = 0x0101;
        P3 = R7;
        P1 = P3 << 1;
        P1 = (P1 + P3) << 2;
        P0 = P0 + P1;
        P0 += -12;
        R4 = 0x1F;
        R5 = 0x7;

        LSETUP (.Lcolumn, .Lcolumn_end) LC0 = P3;
.Lcolumn:
        R0 = B[P2] (Z);
        R1 = B[P2 + 1] (Z);
        R0 <<= 8;
        R0 = R0 | R1;

        /* Stock height record: (PWV5_word >> 2) & 0x1F. */
        R1 = R0 >> 2;
        R1 = R1 & R4;
        W[P0] = R1.L;
        W[P0 + 2] = R6;

        /* Expand each 3-bit component to five bits using abc -> abcab. */
        R2 = R0 >> 13;
        R3 = R2 >> 1;
        R2 <<= 2;
        R2 = R2 | R3;
        R2 <<= 10;

        R3 = R0 >> 10;
        R3 = R3 & R5;
        R1 = R3 >> 1;
        R3 <<= 2;
        R3 = R3 | R1;
        R3 <<= 5;
        R2 = R2 | R3;

        R3 = R0 >> 7;
        R3 = R3 & R5;
        R1 = R3 >> 1;
        R3 <<= 2;
        R3 = R3 | R1;
        R2 = R2 | R3;
        W[P0 + 4] = R2;
        W[P0 + 6] = R6;
        [P0 + 8] = R6;
.Lcolumn_end:
        P2 += -2;
        P0 += -12;

        /* This is the renderer-visible ready flag/count. */
        [P4] = R7;

.Ldone:
        (R7:4, P5:3) = [SP++];
        UNLINK;
        RTS;

        .align 4
/* First-frame memcpy hook. Hide the old records before their arena is reused as
 * the PWV5 receive buffer, then tail-chain to stock memcpy at 0x00D49394.
 */
pwv5_first_copy:
        P0.L = 0x3698;
        P0.H = 0x00CD;
        R3 = 0;
        [P0] = R3;
        JUMP stock_detail_copy;
