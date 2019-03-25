module logpro

go 1.12

replace golang.org/x/crypto v0.0.0-20181127143415-eb0de9b17e85 => github.com/golang/crypto v0.0.0-20181127143415-eb0de9b17e85

replace golang.org/x/net v0.0.0-20181114220301-adae6a3d119a => github.com/golang/net v0.0.0-20181114220301-adae6a3d119a

replace gopkg.in/yaml.v2 v2.2.1 => github.com/go-yaml/yaml v0.0.0-20180328195020-5420a8b6744d

replace gopkg.in/check.v1 v0.0.0-20161208181325-20d25e280405 => github.com/go-check/check v0.0.0-20161208181325-20d25e280405

require (
	github.com/astaxie/beego v1.11.1
	gopkg.in/urfave/cli.v2 v2.0.0-00010101000000-000000000000
	standAlone/utils v0.0.0

)

replace standAlone/utils v0.0.0 => github.com/hexiu/utils v0.0.0-20190315023330-b11afa11734e

replace gopkg.in/urfave/cli.v2 => github.com/urfave/cli v1.20.1-0.20190129195102-5b83c895a70b
