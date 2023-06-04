/* Wrapper macros for liboqs */
#define exit(arg)          sprav_exit(arg)
#define malloc(arg)        sprav_malloc(arg)
#define free(arg)          sprav_free(arg)
/*
#define fopen(a1,a2)       sprav_fopen(a1,a2)
#define fclose(arg)        sprav_fclose(arg)
#define ferror(arg)        sprav_ferror(arg)
#define fread(a1,a2,a3,a4) sprav_fread(a1,a2,a3,a4)
*/
#define perror(arg)        sprav_perror(arg)
