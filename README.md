
# Ryu-based Simple OpenFlow Router 13

This is a simple router to route IPv4. This was created for experimentation and study.

## Usage
You need to write the configuration to `config/config.yaml`
```
$ ryu-manager router.py
```

## Pipeline design
I used [trama book](https://yasuhito.github.io/trema-book/#router13) as a reference.

![pipeline](./doc/images/pipeline.drawio.svg)

※ ACL is a future work in progress.

## Class design
A class is defined for each table, and each table handles the events of its own table_id.
![class](./doc/images/class_design.drawio.svg)

