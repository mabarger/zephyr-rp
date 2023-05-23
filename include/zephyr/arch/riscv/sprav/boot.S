/* Set up PMP to mark prac as execute only and lock it */
la t0, prac_begin
srli t0, t0, 2
csrw pmpaddr0, t0

la t0, prac_end
srli t0, t0, 2
li t1, 0x8C8F
csrw pmpaddr1, t0
csrw pmpcfg0, t1

/* Test accesses to address outside and inside region, the second will fail */
/* 
la t0, prac_begin
sb t1, -1(t0)
sb t1, 0x20(t0)
*/

