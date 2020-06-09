# Minimal makefile for Sphinx documentation
#

# You can set these variables from the command line.
SPHINXOPTS    =
SPHINXBUILD   = sphinx-build
SPHINX_APIDOC = sphinx-apidoc
SOURCEDIR     = source
BUILDDIR      = build

# Put it first so that "make" without argument is like "make help".
help:
	@$(SPHINXBUILD) -M help "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

# Generate API docs automatically, using `sphinx-apidoc`.
apidocs:
	@$(SPHINX_APIDOC) --force --module-first --separate --tocfile index \
		-o "$(SOURCEDIR)" ../linotp \
		"../linotp/*/libfips/" "../linotp/tests/"

.PHONY: help apidocs Makefile

# Catch-all target: route all unknown targets to Sphinx using the new
# "make mode" option.  $(O) is meant as a shortcut for $(SPHINXOPTS).
%: Makefile
	@$(SPHINXBUILD) -M $@ "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)
