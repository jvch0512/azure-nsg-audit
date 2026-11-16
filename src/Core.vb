Option Strict On
Option Explicit On

Imports System
Imports System.Collections.Generic
Imports System.IO
Imports System.Linq
Imports System.Text.Json

Namespace NsgAudit

    Public Class Finding
        Public ReadOnly Property Sev As String
        Public ReadOnly Property Rule As String
        Public ReadOnly Property File As String
        Public ReadOnly Property Where As String
        Public ReadOnly Property Msg As String

        Public Sub New(sev As String, rule As String, file As String, where As String, msg As String)
            Me.Sev = sev
            Me.Rule = rule
            Me.File = file
            Me.Where = where
            Me.Msg = msg
        End Sub
    End Class

    Public Module Core

        Public Function Rank(sev As String) As Integer
            Select Case sev
                Case "critical" : Return 0
                Case "high" : Return 1
                Case "medium" : Return 2
                Case "low" : Return 3
                Case Else : Return 4
            End Select
        End Function

        Private ReadOnly AdminPorts As Integer() = {22, 23, 445, 3389, 5985, 5986}
        Private ReadOnly DbPorts As Integer() = {1433, 1521, 3306, 5432, 6379, 9200, 11211, 27017}
        Private ReadOnly InternetNames As String() = {"*", "internet", "any", "0.0.0.0/0", "0.0.0.0", "::/0"}

        Private Function Prop(el As JsonElement, name As String) As JsonElement?
            If el.ValueKind <> JsonValueKind.Object Then Return Nothing
            Dim v As JsonElement
            If el.TryGetProperty(name, v) Then Return v
            ' case-insensitive fallback
            For Each p In el.EnumerateObject()
                If String.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase) Then Return p.Value
            Next
            Return Nothing
        End Function

        Private Function Str(el As JsonElement, name As String) As String
            Dim v As JsonElement? = Prop(el, name)
            If v.HasValue AndAlso v.Value.ValueKind = JsonValueKind.String Then Return v.Value.GetString().Trim()
            Return ""
        End Function

        ' collects a value given as singular string and/or plural array
        Private Function Strs(el As JsonElement, singular As String, plural As String) As List(Of String)
            Dim res As New List(Of String)()
            Dim s As String = Str(el, singular)
            If s <> "" Then res.Add(s)
            Dim a As JsonElement? = Prop(el, plural)
            If a.HasValue AndAlso a.Value.ValueKind = JsonValueKind.Array Then
                For Each x In a.Value.EnumerateArray()
                    If x.ValueKind = JsonValueKind.String Then res.Add(x.GetString().Trim())
                Next
            End If
            Return res
        End Function

        Public Function IsInternet(prefixes As IEnumerable(Of String)) As Boolean
            Return prefixes.Any(Function(p) InternetNames.Contains(p.ToLowerInvariant()))
        End Function

        ' returns (lo, hi) pairs for a list of port expressions; "*" is 0-65535
        Public Function ParsePorts(exprs As IEnumerable(Of String)) As List(Of Tuple(Of Integer, Integer))
            Dim res As New List(Of Tuple(Of Integer, Integer))()
            For Each e In exprs
                Dim t As String = e.Trim()
                If t = "*" Then
                    res.Add(Tuple.Create(0, 65535))
                ElseIf t.Contains("-") Then
                    Dim parts As String() = t.Split("-"c)
                    Dim lo, hi As Integer
                    If parts.Length = 2 AndAlso Integer.TryParse(parts(0), lo) AndAlso Integer.TryParse(parts(1), hi) AndAlso lo >= 0 AndAlso hi <= 65535 AndAlso lo <= hi Then
                        res.Add(Tuple.Create(lo, hi))
                    End If
                Else
                    Dim p As Integer
                    If Integer.TryParse(t, p) AndAlso p >= 0 AndAlso p <= 65535 Then res.Add(Tuple.Create(p, p))
                End If
            Next
            Return res
        End Function

        Private Function Covers(ranges As List(Of Tuple(Of Integer, Integer)), ports As Integer()) As List(Of Integer)
            Return ports.Where(Function(p) ranges.Any(Function(r) p >= r.Item1 AndAlso p <= r.Item2)).ToList()
        End Function

        Private Sub AuditRule(nsgName As String, rule As JsonElement, file As String, out As List(Of Finding))
            Dim body As JsonElement = If(Prop(rule, "properties"), rule)
            Dim name As String = Str(rule, "name")
            If name = "" Then name = "(unnamed)"
            Dim where As String = file & "#" & nsgName & "/" & name
            Dim access As String = Str(body, "access").ToLowerInvariant()
            Dim direction As String = Str(body, "direction").ToLowerInvariant()
            If access <> "allow" Then Return
            Dim prio As Integer = 0
            Dim pv As JsonElement? = Prop(body, "priority")
            If pv.HasValue AndAlso pv.Value.ValueKind = JsonValueKind.Number Then pv.Value.TryGetInt32(prio)
            If prio >= 65000 Then Return
            Dim proto As String = Str(body, "protocol")
            Dim ports = ParsePorts(Strs(body, "destinationPortRange", "destinationPortRanges"))
            If Str(body, "description") = "" Then
                out.Add(New Finding("low", "NSG006", file, where, name & " is an Allow rule with no description"))
            End If
            If direction = "inbound" Then
                If Not IsInternet(Strs(body, "sourceAddressPrefix", "sourceAddressPrefixes")) Then Return
                Dim admin = Covers(ports, AdminPorts)
                Dim db = Covers(ports, DbPorts)
                Dim allPorts As Boolean = ports.Any(Function(r) r.Item1 = 0 AndAlso r.Item2 = 65535)
                If allPorts Then
                    out.Add(New Finding("high", "NSG003", file, where, name & " allows every port from the internet"))
                ElseIf admin.Count > 0 Then
                    out.Add(New Finding("critical", "NSG001", file, where, name & " exposes admin port " & String.Join(", ", admin) & " to the internet"))
                ElseIf db.Count > 0 Then
                    out.Add(New Finding("high", "NSG002", file, where, name & " exposes database port " & String.Join(", ", db) & " to the internet"))
                ElseIf ports.Any(Function(r) r.Item2 - r.Item1 + 1 > 100) Then
                    out.Add(New Finding("medium", "NSG004", file, where, name & " opens a range of more than 100 ports to the internet"))
                End If
                If allPorts = False AndAlso proto = "*" Then
                    out.Add(New Finding("medium", "NSG005", file, where, name & " allows every protocol from the internet"))
                End If
                If allPorts AndAlso admin.Count > 0 Then
                    out.Add(New Finding("critical", "NSG001", file, where, name & " exposes admin ports to the internet through the any-port rule"))
                End If
            ElseIf direction = "outbound" Then
                Dim dest = Strs(body, "destinationAddressPrefix", "destinationAddressPrefixes")
                If IsInternet(dest) AndAlso ports.Any(Function(r) r.Item1 = 0 AndAlso r.Item2 = 65535) Then
                    out.Add(New Finding("medium", "NSG007", file, where, name & " allows all outbound traffic to the internet"))
                End If
            End If
        End Sub

        Private Function NsgList(root As JsonElement) As List(Of JsonElement)
            Dim res As New List(Of JsonElement)()
            If root.ValueKind = JsonValueKind.Array Then
                For Each x In root.EnumerateArray()
                    res.AddRange(NsgList(x))
                Next
            ElseIf root.ValueKind = JsonValueKind.Object Then
                Dim v As JsonElement? = Prop(root, "value")
                If v.HasValue AndAlso v.Value.ValueKind = JsonValueKind.Array Then
                    res.AddRange(NsgList(v.Value))
                ElseIf Prop(root, "securityRules").HasValue OrElse (Prop(root, "properties").HasValue AndAlso Prop(Prop(root, "properties").Value, "securityRules").HasValue) Then
                    res.Add(root)
                End If
            End If
            Return res
        End Function

        Public Function Audit(text As String, file As String) As List(Of Finding)
            Dim out As New List(Of Finding)()
            Try
                Using doc As JsonDocument = JsonDocument.Parse(text)
                    Dim nsgs = NsgList(doc.RootElement)
                    If nsgs.Count = 0 Then
                        out.Add(New Finding("info", "NSG000", file, file, "no network security groups found, ignored"))
                        Return out
                    End If
                    For Each n In nsgs
                        Dim nm As String = Str(n, "name")
                        If nm = "" Then nm = "(unnamed nsg)"
                        Dim rules As JsonElement? = Prop(n, "securityRules")
                        If Not rules.HasValue Then
                            Dim props As JsonElement? = Prop(n, "properties")
                            If props.HasValue Then rules = Prop(props.Value, "securityRules")
                        End If
                        If rules.HasValue AndAlso rules.Value.ValueKind = JsonValueKind.Array Then
                            For Each r In rules.Value.EnumerateArray()
                                If r.ValueKind = JsonValueKind.Object Then AuditRule(nm, r, file, out)
                            Next
                        End If
                    Next
                End Using
            Catch ex As JsonException
                Return New List(Of Finding) From {New Finding("info", "NSG000", file, file, "not valid JSON, ignored")}
            Catch ex As ArgumentException
                Return New List(Of Finding) From {New Finding("info", "NSG000", file, file, "not valid JSON, ignored")}
            End Try
            Return out
        End Function

        Public Function SortFindings(f As IEnumerable(Of Finding)) As List(Of Finding)
            Return f.OrderBy(Function(x) Rank(x.Sev)).ThenBy(Function(x) x.File, StringComparer.Ordinal).ThenBy(Function(x) x.Rule, StringComparer.Ordinal).ThenBy(Function(x) x.Where, StringComparer.Ordinal).ToList()
        End Function

        Private Sub Walk(dir As String, root As String, depth As Integer, acc As List(Of Tuple(Of String, String)))
            If depth > 30 Then Return
            Try
                For Each f In Directory.GetFiles(dir, "*.json").OrderBy(Function(x) x, StringComparer.Ordinal)
                    If (New FileInfo(f).Attributes And FileAttributes.ReparsePoint) = 0 Then
                        acc.Add(Tuple.Create(Path.GetRelativePath(root, f).Replace("\"c, "/"c), f))
                    End If
                Next
                For Each d In Directory.GetDirectories(dir).OrderBy(Function(x) x, StringComparer.Ordinal)
                    Dim n As String = Path.GetFileName(d)
                    If n <> ".git" AndAlso (New DirectoryInfo(d).Attributes And FileAttributes.ReparsePoint) = 0 Then Walk(d, root, depth + 1, acc)
                Next
            Catch ex As IOException
            Catch ex As UnauthorizedAccessException
            End Try
        End Sub

        Public Function AuditPath(path As String, ByRef fileCount As Integer) As List(Of Finding)
            Dim files As New List(Of Tuple(Of String, String))()
            If Directory.Exists(path) Then
                Walk(path, path, 0, files)
            Else
                files.Add(Tuple.Create(IO.Path.GetFileName(path), path))
            End If
            fileCount = files.Count
            Dim all As New List(Of Finding)()
            For Each t In files
                Dim text As String = ""
                Try
                    If New FileInfo(t.Item2).Length <= 50000000L Then text = File.ReadAllText(t.Item2)
                Catch ex As IOException
                Catch ex As UnauthorizedAccessException
                End Try
                all.AddRange(Audit(text, t.Item1))
            Next
            Return SortFindings(all)
        End Function

    End Module

End Namespace
