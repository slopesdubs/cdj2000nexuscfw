/* Replacement for the stock CALL at GUI address 0x00D0F538.
 * Link at 0x00D0F538 with pwv5_gui_consumer defined as 0x00D4A000.
 */

        .section .text
        .global pwv5_consumer_call_hook
        .extern pwv5_gui_consumer

pwv5_consumer_call_hook:
        CALL pwv5_gui_consumer;
