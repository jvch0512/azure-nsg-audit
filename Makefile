.PHONY: build test sample

build:
	dotnet build src/AzureNsgAudit.vbproj -c Release -o build/out -v q --nologo $(RESTORE)

test: build
	dotnet run --project tests/Tests.vbproj -c Release -v q --nologo $(RESTORE) && bash tests/cli.sh

sample: build
	mkdir -p docs site
	bin/azure-nsg-audit examples > docs/sample-output.txt; true
	bin/azure-nsg-audit examples --tsv > docs/sample-output.tsv; true
	python3 scripts/site.py docs/sample-output.tsv site/index.html "azure-nsg-audit" "Audits Azure network security group exports for internet-facing admin and database ports, any-any allows, wide port ranges and unrestricted egress. Visual Basic .NET." "Synthetic data."
