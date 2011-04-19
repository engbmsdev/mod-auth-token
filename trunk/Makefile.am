## Define compiler debug flags
AM_CFLAGS = $(CXXDEBUGDEFINES)

## Define the source file for the module
noinst_SCRIPTS = mod_auth_token.so

mod_auth_token.so:
	$(APXS) $(APXS_CXX_OPTIONS) $(INCLUDES) $(APR_CFLAGS) $(APR_LIBS) -c mod_auth_token.c

## Define install targets
install: mod_auth_token.so
	$(MKDIR_P) $(DESTDIR)$(APXS_LIBEXECDIR)
	$(APXS) -i -S LIBEXECDIR=$(DESTDIR)$(APXS_LIBEXECDIR) -n mod_auth_token mod_auth_token.la
