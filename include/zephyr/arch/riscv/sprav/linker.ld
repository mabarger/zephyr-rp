	prac : ALIGN(4K)
	{
		prac_begin = .;
		*(prac)

		/* Functions that will be placed in prac */
		/*sprav_attest_region_protected = .;*/
		*(.text.sprav_attest_region_protected);
		*(.text.tc_sha256_*);

		FILL(0x00)
		. = (. + 4K) & ~0xFFF;
	}

	prac_end = .;
