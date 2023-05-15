SECTIONS {
	prac : ALIGN(4K)
	{
		prac_begin = .;
		*(prac)

		FILL(0x00)
		. = (. + 4K) & ~0xFFF;
	}

	prac_end = .;
}
