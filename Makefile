GIT = git
INSTALLFILES=.installfiles
PYTHON ?= python3
override GITHEAD := $(shell test -e .git && $(GIT) rev-parse HEAD)

U := $(shell $(PYTHON) ./setup.py versionup2date >/dev/null 2>&1; echo $$?;)
TESTS = $(wildcard unit-tests/*_test.py)

all:
	$(PYTHON) setup.py build

install: gensrc linstor/consts_githash.py
	$(PYTHON) setup.py install --record $(INSTALLFILES)

uninstall:
	test -f $(INSTALLFILES) && cat $(INSTALLFILES) | xargs rm -rf || true
	rm -f $(INSTALLFILES)

ifneq ($(U),0)
up2date:
	$(error "Update your Version strings/Changelogs")
else
up2date: linstor/consts_githash.py
	$(info "Version strings/Changelogs up to date")
endif

.PHONY: linstor/drbdsetup_options.py
linstor/drbdsetup_options.py:
	linstor-common/gendrbdoptions.py python $@

release: up2date clean
	$(PYTHON) setup.py sdist
	@echo && echo "Did you run distclean?"
	@echo && echo "Did you generate and commit the latest drbdsetup options?"

debrelease:
	echo 'recursive-include debian *' >> MANIFEST.in
	dh_clean || true
	make release
	git checkout MANIFEST.in

.PHONY: gensrc
gensrc:
	make -C linstor-common cleanpython
	make -C linstor-common python

# no gensrc here, that is in debian/rules
deb: up2date
	[ -d ./debian ] || (echo "Your checkout/tarball does not contain a debian directory" && false)
	debuild -i -us -uc -b

# it is up to you (or the buildenv) to provide a distri specific setup.cfg
rpm: gensrc up2date
	$(PYTHON) setup.py bdist_rpm

.PHONY: linstor/consts_githash.py
ifdef GITHEAD
override GITDIFF := $(shell $(GIT) diff --name-only HEAD 2>/dev/null | \
			grep -vxF "MANIFEST.in" | \
			tr -s '\t\n' '  ' | \
			sed -e 's/^/ /;s/ *$$//')
linstor/consts_githash.py:
	@echo "GITHASH = 'GIT-hash: $(GITHEAD)$(GITDIFF)'" > $@
else
linstor/consts_githash.py:
	@echo >&2 "Need a git checkout to regenerate $@"; test -s $@
endif

md5sums:
	CURDATE=$$(date +%s); for i in $$(${GIT} ls-files | sort); do md5sum $$i >> md5sums.$${CURDATE}; done

clean:
	$(PYTHON) setup.py clean

distclean: clean
	git clean -d -f || true

check:
	# currently none
	# $(PYTHON) $(TESTS)

.PHONY: doc upload-doc
doc: gensrc
	make -C doc html

upload-doc: doc
	tmpd=$$(mktemp -p $$PWD -d) && \
	cp -r ./doc/_build/html/* $$tmpd && cd $$tmpd && touch .nojekyll && \
	git init && git add . && git commit -m "gh-pages" && \
	git push -f git@github.com:LINBIT/linstor-api-py.git master:gh-pages && \
	rm -rf $$tmpd
