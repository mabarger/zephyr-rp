	prac : ALIGN(64)
	{
		prac_begin = .;
		*(prac)

		/* Functions that will be placed in prac */
		*(.text.sprav*);
		*(.text.tc_sha256*);
		*(.text.OQS*);
		*(.text.uECC*);

		/* Pad with 0x00 to alignment border */
		FILL(0x00)
		. = (. + 4K) & ~0xFFF;
	  } GROUP_DATA_LINK_IN(IRAM_REGION, ROMABLE_REGION)

	prac_end = .;
