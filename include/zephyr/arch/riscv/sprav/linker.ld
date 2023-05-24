	prac : ALIGN(4K)
	{
		prac_begin = .;
		*(prac)

		/* Functions that will be placed in prac */
		*(.text.sprav*);
		*(.text.tc_sha256*);
		*(.text.uECC*);

		/* Pad with 0x00 to alignment border */
		FILL(0x00)
		. = (. + 4K) & ~0xFFF;
	}

	prac_end = .;
