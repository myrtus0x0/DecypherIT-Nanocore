# DecypherIT-Nanocore

Located in this repo are the tools and resources used to analyze the nanocore sample and CypherIT crypter from this blog post.

## CypherIT
To simplify the CypherIT crypter
```
go run deCypherIT.go -input_file autoit.au3
```

## Nanocore 
Config extract
```
python configExtract.py --sample nanocore.bin --guid a60da4cd-c8b2-44b8-8f62-b12ca6e1251a --dump_dir ./plugins
```