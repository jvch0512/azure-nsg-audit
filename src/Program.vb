Option Strict On
Option Explicit On

Imports System
Imports System.Collections.Generic
Imports System.IO
Imports System.Text

Namespace NsgAudit

    Public Module Program

        Private Function Usage() As Integer
            Console.Error.WriteLine("usage: azure-nsg-audit PATH [--tsv] [--fail-on medium|high|critical]" & vbLf & "Exit: 0 ok, 1 findings at or above --fail-on, 2 bad input.")
            Return 2
        End Function

        Public Function Run(args As String()) As Integer
            Dim path As String = Nothing
            Dim tsv As Boolean = False
            Dim failOn As String = Nothing
            Dim i As Integer = 0
            While i < args.Length
                Dim a As String = args(i)
                If a = "--tsv" Then
                    tsv = True
                ElseIf a = "--fail-on" Then
                    i += 1
                    If i >= args.Length OrElse Not (args(i) = "medium" OrElse args(i) = "high" OrElse args(i) = "critical") Then Return Usage()
                    failOn = args(i)
                ElseIf a.StartsWith("-") Then
                    Return Usage()
                ElseIf path IsNot Nothing Then
                    Return Usage()
                Else
                    path = a
                End If
                i += 1
            End While
            If path Is Nothing Then Return Usage()
            If Not (File.Exists(path) OrElse Directory.Exists(path)) Then
                Console.Error.WriteLine("error: no such file or directory: " & path)
                Return 2
            End If
            Dim n As Integer = 0
            Dim p As String = If(path.Length > 1, path.TrimEnd("/"c), path)
            If p = "" Then p = "/"
            Dim fs As List(Of Finding) = AuditPath(p, n)
            Dim head As String = n & " files, " & fs.Count & " findings"
            Dim sb As New StringBuilder()
            sb.Append(If(tsv, "# " & head, head)).Append(vbLf)
            For Each f In fs
                If tsv Then
                    sb.Append(String.Join(vbTab, {f.Sev, f.Rule, f.Where, f.Msg})).Append(vbLf)
                Else
                    sb.Append(f.Sev.ToUpperInvariant().PadRight(8) & " " & f.Rule & " " & f.Where).Append(vbLf)
                    sb.Append("         " & f.Msg).Append(vbLf)
                End If
            Next
            Console.Out.Write(sb.ToString())
            If failOn IsNot Nothing Then
                For Each f In fs
                    If Rank(f.Sev) <= Rank(failOn) Then Return 1
                Next
            End If
            Return 0
        End Function

        Public Function Main(args As String()) As Integer
            Return Run(args)
        End Function

    End Module

End Namespace
