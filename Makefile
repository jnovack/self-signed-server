include scripts/variables.mk

# Only necessary for Go projects
include scripts/go.mk

.PHONY: build all
.DEFAULT_GOAL := all

all: build

test:
	# Make your own tests

build:
	# Make your own build statements