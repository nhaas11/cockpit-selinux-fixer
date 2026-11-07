NAME      = cockpit-selinux-fixer
VERSION  ?= 0.1.0
PREFIX   ?= /usr
DESTDIR  ?=
PKGDIR    = $(PREFIX)/share/cockpit/selinux-fixer
DEVDIR    = $(HOME)/.local/share/cockpit/selinux-fixer
SOURCES   = src/manifest.json src/index.html src/app.js src/app.css src/sefix.py

.PHONY: all check install uninstall devel-install devel-uninstall dist rpm obs clean

all: check

check:
	python3 src/sefix.py list --all --file tests/sample-audit.log >/dev/null
	python3 -m json.tool src/manifest.json >/dev/null
	python3 -m py_compile src/sefix.py && rm -rf src/__pycache__
	@if command -v node >/dev/null; then node --check src/app.js; else echo "node not found, skipping app.js syntax check"; fi
	@echo "All checks passed."

# System-wide install (as root), also used by the RPM spec.
install:
	install -d $(DESTDIR)$(PKGDIR) $(DESTDIR)$(PREFIX)/bin
	install -m 0644 src/manifest.json src/index.html src/app.js src/app.css $(DESTDIR)$(PKGDIR)/
	install -m 0755 src/sefix.py $(DESTDIR)$(PKGDIR)/
	ln -sf ../share/cockpit/selinux-fixer/sefix.py $(DESTDIR)$(PREFIX)/bin/selinux-fixer

uninstall:
	rm -rf $(DESTDIR)$(PKGDIR) $(DESTDIR)$(PREFIX)/bin/selinux-fixer

# Development: Cockpit loads the page straight from this checkout.
# Edit files, then reload the browser tab.
devel-install:
	mkdir -p $(dir $(DEVDIR))
	ln -sfn $(CURDIR)/src $(DEVDIR)
	@echo "Linked $(DEVDIR) -> $(CURDIR)/src. Log in to Cockpit and open Tools > SELinux Fixer."

devel-uninstall:
	rm -f $(DEVDIR)

dist: check
	mkdir -p dist
	tar --transform 's,^,$(NAME)-$(VERSION)/,' -czf dist/$(NAME)-$(VERSION).tar.gz \
	    Makefile README.md LICENSE $(NAME).spec $(NAME).changes $(SOURCES) tests/sample-audit.log
	@echo dist/$(NAME)-$(VERSION).tar.gz

rpm: dist
	rpmbuild -ba --define "_sourcedir $(CURDIR)/dist" --define "_rpmdir $(CURDIR)/dist" \
	    --define "_srcrpmdir $(CURDIR)/dist" $(NAME).spec
	@find dist -name '*.rpm'

# Files to upload to an OBS package: tarball, spec and changes.
obs: dist
	mkdir -p dist/obs
	cp dist/$(NAME)-$(VERSION).tar.gz $(NAME).spec $(NAME).changes dist/obs/
	@ls -1 dist/obs

clean:
	rm -rf dist src/__pycache__
