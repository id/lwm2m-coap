REBAR3 = rebar3

.PHONY: deps test build

build:
	@$(REBAR3) compile

upgrade:
	@$(REBAR3) upgrade

deps:
	@$(REBAR3) get-deps

clean:
	@$(REBAR3) clean

distclean: clean
	@$(REBAR3) delete-deps

test:
	@$(REBAR3) eunit

xref:
	@$(REBAR3) xref

ct:
	@$(REBAR3) ct

dialyzer:
	@$(REBAR3) dialyzer

release:
	@$(REBAR3) release

dist:
	@$(REBAR3) tar

# end of file
