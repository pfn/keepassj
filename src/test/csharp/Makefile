test.exe: test.cs
	@csc /nologo /out:test.exe /r:KeePassLib.dll test.cs

test: test.exe
	./test

clean:
	rm test.exe
