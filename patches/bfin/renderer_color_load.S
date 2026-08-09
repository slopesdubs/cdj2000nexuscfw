/* Replacement for GUI 0x00D2E2B8..0x00D2E2BE.
 * P3 is the current record index, P4 is P3*2, and P2 is record base +4.
 */

        .section .text
        .global pwv5_renderer_color_load

pwv5_renderer_color_load:
        P1 = P3;
        P1 = (P1 + P4) << 2;
        P1 = P2 + P1;
        R0.L = W[P1];
