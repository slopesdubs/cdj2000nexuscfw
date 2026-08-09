/* Replacement for the first-frame memcpy CALL at GUI address 0x00D0FC22. */

        .section .text
        .global pwv5_first_copy_call_hook
        .extern pwv5_first_copy

        /* Link section at 0x00D0FC20 so the call itself can start at +2. */
        NOP;
pwv5_first_copy_call_hook:
        CALL pwv5_first_copy;
