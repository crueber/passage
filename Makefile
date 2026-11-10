.PHONY: css themes assets build test vet

css:
	./tools/build-css.sh

# Theme stylesheets are plain CSS custom-property overrides — no Tailwind
# involvement. Concatenates internal/web/ui/themes/*.css into static/themes.css.
themes:
	./tools/build-themes.sh

# Rebuild every generated stylesheet (Tailwind components + themes).
assets: css themes

build:
	CGO_ENABLED=0 go build ./...

test:
	go test -race ./...

vet:
	go vet ./...
