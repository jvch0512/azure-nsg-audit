Option Strict On
Option Explicit On

Imports System
Imports System.Collections.Generic
Imports System.Linq
Imports System.Text
Imports NsgAudit

Module Tests
    Dim passed As Integer = 0
    Dim failed As Integer = 0

    Sub Check(ok As Boolean, name As String)
        If ok Then
            passed += 1
        Else
            failed += 1
            Console.WriteLine("FAIL: " & name)
        End If
    End Sub

    Function Rules(text As String) As String
        Return String.Join(",", Audit(text, "t.json").Select(Function(f) f.Rule).OrderBy(Function(x) x, StringComparer.Ordinal))
    End Function

    ' one NSG with one rule; fields is the JSON body of the rule
    Function Nsg(fields As String) As String
        Return "{""name"":""n"",""securityRules"":[{""name"":""r"",""priority"":100," & fields & "}]}"
    End Function

    Function Inb(src As String, port As String, Optional proto As String = "Tcp", Optional desc As String = "d") As String
        Dim p As String = If(port.StartsWith("["), """destinationPortRanges"":" & port, """destinationPortRange"":""" & port & """")
        Dim s As String = If(src.StartsWith("["), """sourceAddressPrefixes"":" & src, """sourceAddressPrefix"":""" & src & """")
        Dim d As String = If(desc = "", "", ",""description"":""" & desc & """")
        Return Nsg("""direction"":""Inbound"",""access"":""Allow"",""protocol"":""" & proto & """," & s & "," & p & d)
    End Function

    Function Main() As Integer
        ' clean
        Check(Rules(Inb("10.0.0.0/8", "22")) = "", "internal ssh is fine")
        Check(Rules(Inb("Internet", "443")) = "", "public https is fine")
        Check(Rules(Inb("VirtualNetwork", "*")) = "", "vnet any is fine")
        Check(Rules(Inb("AzureLoadBalancer", "*")) = "", "load balancer tag is not the internet")

        ' NSG001
        For Each port In {"22", "23", "445", "3389", "5985", "5986"}
            Check(Rules(Inb("*", port)) = "NSG001", "admin port " & port)
        Next
        For Each src In {"*", "Internet", "internet", "Any", "0.0.0.0/0", "0.0.0.0", "::/0"}
            Check(Rules(Inb(src, "22")) = "NSG001", "internet source " & src)
        Next
        Check(Rules(Inb("[""10.0.0.0/8"",""0.0.0.0/0""]", "22")) = "NSG001", "internet among several sources")
        Check(Rules(Inb("*", "[""80"",""3389""]")) = "NSG001", "admin port in port list")
        Check(Rules(Inb("*", "20-30")) = "NSG001", "admin port inside a range")
        Check(Audit(Inb("*", "22"), "t.json")(0).Sev = "critical", "NSG001 is critical")

        ' NSG002
        For Each port In {"1433", "1521", "3306", "5432", "6379", "9200", "11211", "27017"}
            Check(Rules(Inb("*", port)) = "NSG002", "db port " & port)
        Next

        ' NSG003 / NSG004 / NSG005
        Check(Rules(Inb("*", "*")) = "NSG001,NSG003", "any port from anywhere also hits admin")
        Check(Rules(Inb("*", "0-65535")) = "NSG001,NSG003", "full range is any port")
        Check(Rules(Inb("*", "8000-8200")) = "NSG004", "wide range")
        Check(Rules(Inb("*", "8000-8100")) = "NSG004", "101 ports is wide")
        Check(Rules(Inb("*", "8000-8099")) = "", "100 ports is not wide")
        Check(Rules(Inb("*", "8080", "*")) = "NSG005", "protocol star")
        Check(Rules(Inb("10.0.0.0/8", "8080", "*")) = "", "protocol star from internal source")

        ' NSG006
        Check(Rules(Inb("10.0.0.0/8", "443", "Tcp", "")) = "NSG006", "no description")
        Check(Rules(Nsg("""direction"":""Inbound"",""access"":""Deny"",""protocol"":""*"",""sourceAddressPrefix"":""*"",""destinationPortRange"":""*""")) = "", "deny rules are ignored")

        ' NSG007
        Dim egress As String = Nsg("""direction"":""Outbound"",""access"":""Allow"",""protocol"":""*"",""destinationAddressPrefix"":""Internet"",""destinationPortRange"":""*"",""description"":""d""")
        Check(Rules(egress) = "NSG007", "unrestricted egress")
        Dim egress443 As String = Nsg("""direction"":""Outbound"",""access"":""Allow"",""protocol"":""Tcp"",""destinationAddressPrefix"":""Internet"",""destinationPortRange"":""443"",""description"":""d""")
        Check(Rules(egress443) = "", "restricted egress")
        Dim egressInternal As String = Nsg("""direction"":""Outbound"",""access"":""Allow"",""protocol"":""*"",""destinationAddressPrefix"":""10.0.0.0/8"",""destinationPortRange"":""*"",""description"":""d""")
        Check(Rules(egressInternal) = "", "egress to internal range")

        ' default rules and priorities
        Check(Rules("{""name"":""n"",""securityRules"":[{""name"":""AllowAll"",""priority"":65000,""direction"":""Inbound"",""access"":""Allow"",""protocol"":""*"",""sourceAddressPrefix"":""*"",""destinationPortRange"":""*""}]}") = "", "default rules ignored")
        Check(Rules("{""name"":""n"",""securityRules"":[{""name"":""r"",""priority"":64999,""direction"":""Inbound"",""access"":""Allow"",""protocol"":""Tcp"",""sourceAddressPrefix"":""*"",""destinationPortRange"":""22"",""description"":""d""}]}") = "NSG001", "priority 64999 is custom")

        ' export shapes
        Dim armRule As String = "{""name"":""r"",""properties"":{""priority"":100,""direction"":""Inbound"",""access"":""Allow"",""protocol"":""Tcp"",""sourceAddressPrefix"":""*"",""destinationPortRange"":""22"",""description"":""d""}}"
        Check(Rules("{""name"":""n"",""properties"":{""securityRules"":[" & armRule & "]}}") = "NSG001", "ARM properties shape")
        Check(Rules("[" & Inb("*", "22") & "," & Inb("*", "3306") & "]") = "NSG001,NSG002", "array of NSGs")
        Check(Rules("{""value"":[" & Inb("*", "22") & "]}") = "NSG001", "value wrapper")
        Check(Rules(Inb("*", "22").Replace("""direction""", """Direction""")) = "NSG001", "property names are case-insensitive")
        Check(Rules(Inb("*", "22").Replace("""Allow""", """allow""")) = "NSG001", "access value case-insensitive")

        ' where / labels
        Dim f1 = Audit(Inb("*", "22"), "x.json")(0)
        Check(f1.Where = "x.json#n/r", "where has nsg and rule")
        Check(f1.File = "x.json", "file")

        ' NSG000
        Check(Rules("") = "NSG000", "empty input")
        Check(Rules("{nope") = "NSG000", "invalid json")
        Check(Rules("[]") = "NSG000", "empty array")
        Check(Rules("42") = "NSG000", "number root")
        Check(Rules("null") = "NSG000", "null root")
        Check(Rules("{""a"":1}") = "NSG000", "unrelated object")
        Check(Audit("", "e")(0).Sev = "info", "NSG000 is info")

        ' wrong types
        Check(Rules("{""securityRules"":""x""}") = "", "securityRules string")
        Check(Rules("{""securityRules"":[1,null,""a"",[]]}") = "", "non-object rules")
        Check(Rules("{""securityRules"":[{""priority"":""x"",""direction"":5,""access"":[],""destinationPortRange"":{}}]}") = "", "wrong field types")
        Check(Rules(Inb("*", "abc")) = "", "garbage port")
        Check(Rules(Inb("*", "10-5")) = "", "inverted range")
        Check(Rules(Inb("*", "99999")) = "", "port out of range")

        ' port parsing
        Check(ParsePorts({"*"}).Count = 1 AndAlso ParsePorts({"*"})(0).Item2 = 65535, "parse star")
        Check(ParsePorts({"80", "443-445"}).Count = 2, "parse list")
        Check(ParsePorts({"-", "a-b", "1-2-3", ""}).Count = 0, "parse garbage")
        Check(IsInternet({"10.0.0.0/8", "INTERNET"}), "IsInternet case-insensitive")
        Check(Not IsInternet({"10.0.0.0/8"}), "internal is not internet")

        ' sorting
        Dim list As New List(Of Finding) From {
            New Finding("low", "B", "a", "a", ""), New Finding("high", "A", "z", "z", ""),
            New Finding("high", "A", "a", "a", ""), New Finding("critical", "Z", "z", "z", "")}
        Check(String.Join(" ", SortFindings(list).Select(Function(f) f.Sev & f.File)) = "criticalz higha highz lowa", "sort order")
        Check(Rank("critical") < Rank("high") AndAlso Rank("low") < Rank("info"), "rank order")

        ' deep nesting
        Check(Rules(New String("["c, 5000) & New String("]"c, 5000)) = "NSG000", "deeply nested JSON")

        ' fuzz
        Dim rnd As New Random(7)
        Dim bits As String() = {"{", "}", "[", "]", ",", ":", """securityRules""", """access""", """Allow""", """direction""", """Inbound""", """sourceAddressPrefix""", """*""", """destinationPortRange""", """22""", "1", "null", "true", """name"""}
        Dim crashed As Boolean = False
        For i = 1 To 3000
            Dim sb As New StringBuilder()
            For j = 1 To rnd.Next(1, 40)
                sb.Append(bits(rnd.Next(bits.Length)))
            Next
            Try
                Audit(sb.ToString(), "f.json")
            Catch ex As Exception
                crashed = True
            End Try
        Next
        Dim valid As String = Inb("*", "22")
        For i = 0 To valid.Length
            Try
                Audit(valid.Substring(0, i), "f.json")
            Catch ex As Exception
                crashed = True
            End Try
        Next
        Check(Not crashed, "3000 random and truncated inputs do not throw")

        Console.WriteLine(passed & " passed, " & failed & " failed")
        Return If(failed = 0, 0, 1)
    End Function
End Module
