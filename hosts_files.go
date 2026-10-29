package main

// hosts_files.go — статические записи из файлов формата /etc/hosts.
//
// Зачем: одна и та же запись нужна и резолверу, и системе, а /etc/hosts
// контейнерам не достаётся. Файлы читаются при загрузке конфига (и при каждом
// SIGHUP), а изменение mtime/size подхватывается само — без рестарта.
//
// Правила:
//   - строка: IP имя [алиасы...], '#' начинает комментарий;
//   - каталог в hosts_files читается целиком: все обычные файлы внутри, без
//     рекурсии, в алфавитном порядке;
//   - первое вхождение имени выигрывает (как в классическом /etc/hosts);
//   - явная запись из секции hosts в YAML главнее любого файла;
//   - мусор в файле — ошибка с путём и номером строки, а не тихий пропуск.

import (
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// hostsFileStat — что дал один файл: сколько записей взято, сколько
// перекрыто явными записями или более ранним файлом.
type hostsFileStat struct {
	Path     string
	Entries  int
	Shadowed int
	Err      error
	ModTime  time.Time
	Size     int64
}

// hostsFilePaths разворачивает HostsFiles: каталоги дают лежащие в них
// обычные файлы (без рекурсии, по алфавиту), файлы остаются как есть.
func (c *Config) hostsFilePaths() []string {
	var out []string
	for _, p := range c.HostsFiles {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		fi, err := os.Stat(p)
		if err != nil || !fi.IsDir() {
			out = append(out, p)
			continue
		}
		ents, err := os.ReadDir(p)
		if err != nil {
			out = append(out, p) // ошибку покажет loadHostsFiles
			continue
		}
		var names []string
		for _, e := range ents {
			if e.IsDir() {
				continue
			}
			names = append(names, filepath.Join(p, e.Name()))
		}
		sort.Strings(names)
		out = append(out, names...)
	}
	return out
}

// loadHostsFiles подмешивает записи из файлов в c.Hosts.
func (c *Config) loadHostsFiles() error {
	c.hostsFiles = nil
	if len(c.HostsFiles) == 0 {
		return nil
	}
	if c.Hosts == nil {
		c.Hosts = map[string]string{}
	}

	explicit := make(map[string]bool, len(c.Hosts))
	for k := range c.Hosts {
		explicit[strings.ToLower(strings.TrimSuffix(k, "."))] = true
	}
	seen := make(map[string]string) // имя -> файл, из которого взяли

	for _, path := range c.hostsFilePaths() {
		st := hostsFileStat{Path: path}
		fi, err := os.Stat(path)
		if err != nil {
			st.Err = err
			c.hostsFiles = append(c.hostsFiles, st)
			continue
		}
		st.ModTime, st.Size = fi.ModTime(), fi.Size()

		data, err := os.ReadFile(path)
		if err != nil {
			st.Err = err
			c.hostsFiles = append(c.hostsFiles, st)
			continue
		}

		for i, line := range strings.Split(string(data), "\n") {
			if h := strings.IndexByte(line, '#'); h >= 0 {
				line = line[:h]
			}
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			ip := net.ParseIP(fields[0])
			if ip == nil {
				return fmt.Errorf("%s:%d: не адрес: %q", path, i+1, fields[0])
			}
			for _, name := range fields[1:] {
				key := strings.ToLower(strings.TrimSuffix(name, "."))
				if key == "" {
					continue
				}
				if explicit[key] {
					st.Shadowed++
					continue
				}
				if _, ok := seen[key]; ok {
					st.Shadowed++
					continue
				}
				seen[key] = path
				c.Hosts[key] = ip.String()
				st.Entries++
			}
		}
		c.hostsFiles = append(c.hostsFiles, st)
	}
	return nil
}

// hostsFromFiles — сколько записей пришло из файлов (для логов и -check).
func (c *Config) hostsFromFiles() int {
	n := 0
	for _, st := range c.hostsFiles {
		n += st.Entries
	}
	return n
}

// hostsFromConfig — сколько записей задано явно в YAML.
func (c *Config) hostsFromConfig() int {
	return len(c.Hosts) - c.hostsFromFiles()
}

// hostsFilesBrief — краткая сводка по файлам для строки лога.
func (c *Config) hostsFilesBrief() string {
	if len(c.hostsFiles) == 0 {
		return ""
	}
	parts := make([]string, 0, len(c.hostsFiles))
	for _, st := range c.hostsFiles {
		if st.Err != nil {
			parts = append(parts, st.Path+"=ошибка")
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%d", st.Path, st.Entries))
	}
	return ": " + strings.Join(parts, ", ")
}

// liveHostsSignature — текущие mtime/size файлов на диске. Сравнивается с
// загруженными: расхождение значит, что файл правили после старта.
func liveHostsSignature(c *Config) string {
	var b strings.Builder
	for _, p := range c.hostsFilePaths() {
		fi, err := os.Stat(p)
		if err != nil {
			fmt.Fprintf(&b, "%s:err;", p)
			continue
		}
		fmt.Fprintf(&b, "%s:%d:%d;", p, fi.ModTime().UnixNano(), fi.Size())
	}
	return b.String()
}

// loadedHostsSignature — то же, но по состоянию на момент загрузки конфига.
func loadedHostsSignature(c *Config) string {
	var b strings.Builder
	for _, st := range c.hostsFiles {
		fmt.Fprintf(&b, "%s:%d:%d;", st.Path, st.ModTime.UnixNano(), st.Size)
	}
	return b.String()
}

// watchHostsFiles перечитывает конфиг, когда hosts-файл изменился на диске.
// Опрос раз в 5 с: SIGHUP остаётся ручным способом, это — автоматический.
func watchHostsFiles() {
	const every = 5 * time.Second
	t := time.NewTicker(every)
	defer t.Stop()

	baseline := func() string {
		cur, _, _ := app.snapshot()
		if cur == nil {
			return ""
		}
		return loadedHostsSignature(cur)
	}
	last := baseline()

	for {
		select {
		case <-t.C:
			cur, _, _ := app.snapshot()
			if cur == nil {
				continue
			}
			got := liveHostsSignature(cur)
			if got == last || got == "" {
				continue
			}
			log.Printf("hosts_files: файл изменился — перечитываю конфиг")
			if err := reload(); err != nil {
				log.Printf("hosts_files: перечитывание не удалось: %v", err)
				last = got // не долбить одним и тем же каждые 5 с
				continue
			}
			last = baseline()
		case <-stopPurge:
			return
		}
	}
}
