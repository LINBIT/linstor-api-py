INSTALLFILES=.installfiles
PYTHON ?= python3

TESTS = $(wildcard unit-tests/*_test.py)

all:
	$(PYTHON) setup.py build

install: gensrc
	$(PYTHON) setup.py install --record $(INSTALLFILES)

uninstall:
	test -f $(INSTALLFILES) && cat $(INSTALLFILES) | xargs rm -rf || true
	rm -f $(INSTALLFILES)

.PHONY: linstor/drbdsetup_options.py
linstor/drbdsetup_options.py:
	linstor-common/gendrbdoptions.py python $@

release: clean
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
deb:
	[ -d ./debian ] || (echo "Your checkout/tarball does not contain a debian directory" && false)
	debuild -i -us -uc -b

# it is up to you (or the buildenv) to provide a distri specific setup.cfg
rpm: gensrc
	$(PYTHON) setup.py bdist_rpm

md5sums:
	CURDATE=$$(date +%s); for i in $$(git ls-files | sort); do md5sum $$i >> md5sums.$${CURDATE}; done

clean:
	$(PYTHON) setup.py clean

distclean: clean
	git clean -d -f || true

.PHONY: doc upload-doc
doc: gensrc
	make -C doc html

upload-doc: doc
	tmpd=$$(mktemp -p $$PWD -d) && \
	cp -r ./doc/_build/html/* $$tmpd && cd $$tmpd && touch .nojekyll && \
	git init && git add . && git commit -m "gh-pages" && \
	git push -f git@github.com:LINBIT/linstor-api-py.git master:gh-pages && \
	rm -rf $$tmpd
