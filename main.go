package main

import (
	"crypto/md5"
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var colorReset = "\033[0m"
var colorRed = "\033[31m"
var colorRedBold = "\033[1;31m"
var colorBrown = "\033[33m"
var colorBlue = "\033[34m"
var colorBlueBold = "\033[1;34m"
var colorCyan = "\033[36m"
var colorCyanBold = "\033[1;36m"
var colorPurple = "\033[1;35m"

func APKHunt_Intro_Func() {
	log.SetFlags(0)
	fmt.Printf(string(colorBlue))
	log.Println(`
	_ _   __ __  _   __  
   / _ \ | _ _ \| | / / 
  / /_\ \| |_/ /| |/ /  
  |  _  ||  __/ |    \  
  | | | || |    | |\  \ 
  \_| |_/\_|    \_| \_/ 
    ---------------------
    OWASP MASVS Static Analyzer                                
        `)
	fmt.Printf(string(colorReset))
	log.Println("[+] a comprehensive static code analysis tool for Android apps")
	log.Println("[+] Based on: OWASP MASVS - https://mobile-security.gitbook.io/masvs/")
	log.Println("[+] Author: Sumit Kalaria & Mrunal Chawda")
	log.Println("[*] Connect: Please do write to us for any suggestions/feedback.")
}

func APKHunt_basic_req_checks() {

	// OS type check
	if runtime.GOOS != "linux" {
		APKHunt_Intro_Func()
		fmt.Println("\n[+] Checking if APKHunt is being executed on Linux OS or not...")
		fmt.Println("[!] Linux OS has not been identified! \n[!] Exiting...")
		fmt.Println("\n[+] It is recommended to execute APKHunt on Kali Linux OS.")
		os.Exit(0)
	}

	//grep/jadx/dex2jar filepath check
	requiredUtilities := []string{"grep", "jadx", "d2j-dex2jar"}
	for _, utility := range requiredUtilities {
		_, err := exec.LookPath(utility)
		if err != nil {
			APKHunt_Intro_Func()
			switch utility {
			case "grep":
				fmt.Printf("\n[!] grep utility has not been observed. \n[!] Kindly install it first! \n[!] Exiting...")
			case "jadx":
				fmt.Printf("\n[!] jadx decompiler has not been observed. \n[!] Kindly install it first! \n[!] Exiting...")
			case "d2j-dex2jar":
				fmt.Printf("\n[!] dex2jar has not been observed. \n[!] Kindly install it first! \n[!] Exiting...")
			}
			os.Exit(0)
		}
	}
}

func APKHunt_help() {
	fmt.Printf(string(colorBrown))
	fmt.Println("\n    APKHunt Usage:")
	fmt.Printf(string(colorReset))
	fmt.Println("\t  go run APKHunt.go [options] {.apk file}")
	fmt.Printf(string(colorBrown))
	fmt.Println("\n    Options:")
	fmt.Printf(string(colorReset))
	fmt.Println("\t -h     For help")
	fmt.Println("\t -p     Provide a single apk file-path")
	fmt.Println("\t -m     Provide the folder-path for multiple apk scanning")
	fmt.Println("\t -l     For logging (.txt file)")
	fmt.Printf(string(colorBrown))
	fmt.Println("\n    Examples:")
	fmt.Printf(string(colorReset))
	fmt.Println("\t APKHunt.go -p /Downloads/android_app.apk")
	fmt.Println("\t APKHunt.go -p /Downloads/android_app.apk -l")
	fmt.Println("\t APKHunt.go -m /Downloads/android_apps/")
	fmt.Println("\t APKHunt.go -m /Downloads/android_apps/ -l")
	fmt.Printf(string(colorBrown))
	fmt.Println("\n    Note:")
	fmt.Printf(string(colorReset))
	fmt.Println("\t - Tested on linux only!")
	fmt.Println("\t - Keep tools such as jadx, dex2jar, go, grep, etc.! installed")
}
func checkAPKIntegrity(fileA, fileB string) (bool, error) {
	// Hàm phụ để tính toán giá trị hash SHA-256 của một file
	calculateFileHash := func(filename string) (string, error) {
		file, err := os.Open(filename)
		if err != nil {
			return "", err
		}
		defer file.Close()

		hash := sha256.New()
		_, err = io.Copy(hash, file)
		if err != nil {
			return "", err
		}

		return fmt.Sprintf("%x", hash.Sum(nil)), nil
	}

	// Tính toán giá trị hash cho hai file
	hashA, err := calculateFileHash(fileA)
	if err != nil {
		return false, err
	}

	hashB, err := calculateFileHash(fileB)
	if err != nil {
		return false, err
	}
	// So sánh giá trị hash
	return hashA == hashB, nil
}
func checkfile() {
	// OWASP MASVS - V8: Resilience Requirements
	log.Println("\n")
	fmt.Printf(string(colorBlueBold))
	log.Println(`[+] Hunting begins based on "V8: Resilience Requirements"`)
	fmt.Printf(string(colorReset))
	log.Println("[+] -----------------------------------------------------")

	// MASVS V8 - MSTG-RESILIENCE-3 - File Integrity Checks
	if len(os.Args) < 7 {
		fmt.Println("Usage: yourprogram -check -p <path_to_fileA> -p1 <path_to_fileB>")
		return
	}

	var fileA, fileB string
	var checkFlag bool

	// Xử lý đối số dòng lệnh
	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "-check":
			checkFlag = true
		case "-p":
			if i+1 < len(os.Args) {
				fileA = os.Args[i+1]
				i++
			} else {
				fmt.Println("Missing value for -p")
				return
			}
		case "-p1":
			if i+1 < len(os.Args) {
				fileB = os.Args[i+1]
				i++
			} else {
				fmt.Println("Missing value for -p1")
				return
			}
		}
	}

	if !checkFlag {
		fmt.Println("-check argument is required")
		return
	}

	if fileA == "" || fileB == "" {
		fmt.Println("Both -p and -p1 arguments are required")
		return
	}

	isValid, err := checkAPKIntegrity(fileA, fileB)
	if err != nil {
		fmt.Printf("Lỗi: %v\n", err)
		return
	}

	if isValid {
		fmt.Println("File B là bản sao chính xác của File A.")
	} else {
		fmt.Println("File B đã bị thay đổi.")
	}
}

func main() {

	// APKHunt Intro
	//APKHunt_Intro_Func()

	//APKHunt basic requirement checks
	APKHunt_basic_req_checks()

	//taking command-line arguments
	//checking arguments length
	argLength := len(os.Args[1:])
	if argLength == 0 {
		APKHunt_Intro_Func()
		fmt.Println("\n[!] Kindly provide the valid arguments/path. \n[!] Please use -h switch to know how-about the APKHunt!")
		os.Exit(0)
	}

	//checking for the first argument

	FirstArg := os.Args[1]

	if FirstArg == "-check" {
		APKHunt_Intro_Func()
		checkfile()
		os.Exit(0)
	}

	if FirstArg == "-h" {
		APKHunt_Intro_Func()
		APKHunt_help()
		os.Exit(0)
	}

	if ((FirstArg != "-h") && (len(os.Args[2:]) == 0)) || ((FirstArg != "-p") && (len(os.Args[2:]) == 0)) || ((FirstArg != "-m") && (len(os.Args[2:]) == 0)) || ((FirstArg != "-l") && (len(os.Args[2:]) == 0)) {
		APKHunt_Intro_Func()
		fmt.Println("\n[!] Kindly provide the valid arguments/path. \n[!] Please use -h switch to know how-about the APKHunt!")
		os.Exit(0)
	}

	//cheking for valid arguments/path
	if ((FirstArg == "-p") && (len(os.Args[2:]) == 0)) || ((FirstArg == "-m") && (len(os.Args[2:]) == 0)) || ((FirstArg == "-l") && (len(os.Args[2:]) == 0)) || (FirstArg == "-l" && os.Args[2] == "-p" && len(os.Args[3:]) == 0) || (FirstArg == "-l" && os.Args[2] == "-m" && len(os.Args[3:]) == 0) {
		APKHunt_Intro_Func()
		fmt.Println("\n[!] Kindly provide the valid arguments/path. \n[!] Please use -h switch to know how-about the APKHunt!")
		os.Exit(0)
	}

	//checking for apk path and log switches
	if (FirstArg == "-p") && (os.Args[2] != "") && (len(os.Args[3:]) == 0) {
		apkpath := os.Args[2]
		log.SetFlags(0)
		APKHunt_Intro_Func()
		APKHunt_core(apkpath)
		os.Exit(0)
	}
	if (FirstArg == "-p") && (os.Args[2] != "") && (os.Args[3] == "-l") {
		apkpath := os.Args[2]
		APKHunt_core_log(apkpath)
		//APKHunt_Intro_Func()
		APKHunt_core(apkpath)
		os.Exit(0)
	}

	if (FirstArg == "-l") && (os.Args[2] == "-p") && (os.Args[3] != "") {
		apkpath := os.Args[3]
		//APKHunt_Intro_Func()
		APKHunt_core_log(apkpath)
		APKHunt_core(apkpath)
		os.Exit(0)
	}

	//checking for multiple apks and log switches
	if (FirstArg == "-m") && (os.Args[2] != "") && (len(os.Args[3:]) == 0) {
		apkpath := os.Args[2]
		log.SetFlags(0)
		APKHunt_Intro_Func()

		if _, err := os.Stat(apkpath); err != nil {
			if os.IsNotExist(err) {
				fmt.Printf("\n[!] Given file-path '%s' does not exist. \n[!] Kindly verify the path/filename! \n[!] Exiting...", apkpath)
				os.Exit(0)
			}
		}

		apkFiles := []string{}
		countAPK := 0

		filepath.Walk(apkpath, func(path string, info os.FileInfo, err error) error {
			if filepath.Ext(path) == ".apk" {
				apkFiles = append(apkFiles, path)
				countAPK++
			}
			return nil
		})
		fmt.Printf(string(colorBrown))
		fmt.Printf("\n==>> Total number of APK files: %d \n\n", countAPK)
		fmt.Printf(string(colorReset))
		if countAPK == 0 {
			fmt.Println("[!] No APK files found in the given directory. \n[!] Kindly verify the path/directory! \n[!] Exiting...")
			os.Exit(0)
		}

		fmt.Printf(string(colorBrown))
		fmt.Println("==>> List of the APK files:")
		fmt.Printf(string(colorReset))
		countAPKfiles := 0
		for _, apkPath := range apkFiles {
			countAPKfiles++
			fmt.Println("    ", countAPKfiles, filepath.Base(apkPath))
		}
		fmt.Printf("\n")

		countScanAPK := 0
		for _, apkPath := range apkFiles {
			countScanAPK++
			fmt.Printf(string(colorBrown))
			fmt.Println("==>> Scan has been started for the app:", countScanAPK, "-", filepath.Base(apkPath))
			fmt.Printf(string(colorReset))
			//APKHunt_core_log(apkPath)
			APKHunt_core(apkPath)
		}
		os.Exit(0)
	}

	if (FirstArg == "-m" && os.Args[2] != "" && os.Args[3] == "-l") || (FirstArg == "-l" && os.Args[2] == "-m" && os.Args[3] != "") {
		var apkpath string
		if FirstArg == "-m" {
			apkpath = os.Args[2]
		} else {
			apkpath = os.Args[3]
		}

		//APKHunt_Intro_Func()

		if _, err := os.Stat(apkpath); err != nil {
			if os.IsNotExist(err) {
				fmt.Printf("\n[!] Given file-path '%s' does not exist. \n[!] Kindly verify the path/filename! \n[!] Exiting...", apkpath)
				os.Exit(0)
			}
		}

		apkFiles := []string{}
		countAPK := 0
		filepath.Walk(apkpath, func(path string, info os.FileInfo, err error) error {
			if filepath.Ext(path) == ".apk" {
				apkFiles = append(apkFiles, path)
				countAPK++
			}
			return nil
		})
		fmt.Printf(string(colorBrown))
		fmt.Printf("\n==>> Total number of APK files: %d \n\n", countAPK)
		fmt.Printf(string(colorReset))
		if countAPK == 0 {
			fmt.Println("[!] No APK files found in the given directory. \n[!] Kindly verify the path/directory! \n[!] Exiting...")
			os.Exit(0)
		}

		fmt.Printf(string(colorBrown))
		fmt.Println("==>> List of the APK files:")
		fmt.Printf(string(colorReset))
		countAPKfiles := 0
		for _, apkPath := range apkFiles {
			countAPKfiles++
			fmt.Println("    ", countAPKfiles, filepath.Base(apkPath))
		}
		fmt.Printf("\n")

		countScanAPK := 0
		for _, apkPath := range apkFiles {
			countScanAPK++
			fmt.Printf(string(colorBrown))
			fmt.Println("==>> Scan has been started for the app:", countScanAPK, "-", filepath.Base(apkPath))
			fmt.Printf(string(colorReset))
			APKHunt_core_log(apkPath)
			APKHunt_core(apkPath)
		}
		os.Exit(0)
	}
}

func APKHunt_core_log(apkpath string) {
	theTime := time.Now()
	time_year := strconv.Itoa(theTime.Year())
	time_month := strconv.Itoa(int(theTime.Month()))
	time_day := strconv.Itoa(int(theTime.Day()))
	time_hour := strconv.Itoa(int(theTime.Hour()))
	time_minute := strconv.Itoa(int(theTime.Minute()))
	time_second := strconv.Itoa(int(theTime.Second()))
	ctime := time_year + "-" + time_month + "-" + time_day + "_" + time_hour + "-" + time_minute + "-" + time_second
	apk_file_name := strings.TrimSuffix(filepath.Base(apkpath), filepath.Ext(filepath.Base(apkpath)))
	log_file_path := filepath.Dir(apkpath) + `/APKHunt_` + apk_file_name + `_` + ctime + `.txt`

	log_file, log_file_err := os.OpenFile(log_file_path, os.O_CREATE|os.O_RDWR, 0644)
	if log_file_err != nil {
		log.Fatal(log_file_err)
	}
	log.SetFlags(0)
	mw := io.MultiWriter(os.Stdout, log_file)
	log.SetOutput(mw)

	APKHunt_Intro_Func()
	log.Println("\n[+] Log-file path:", log_file_path)
	//APKHunt_core(apkpath)
}

func APKHunt_core(apkpath string) {

	//APK filepath check
	if _, err := os.Stat(apkpath); err != nil {
		if os.IsNotExist(err) {
			log.Printf("\n[!] Given file-path '%s' does not exist. \n[!] Kindly verify the path/filename! \n[!] Exiting...", apkpath)
			os.Exit(0)
		}
	}
	if filepath.Ext(apkpath) != ".apk" {
		log.Printf("\n[!] Given file '%s' does not seem to be an apk file. \n[!] Kindly verify the file! \n[!] Exiting...", apkpath)
		os.Exit(0)
	}

	start_time := time.Now()
	log.Println("\n[+] Scan has been started at:", start_time)

	// APK filepath analysis
	apkpathbase := filepath.Base(apkpath)
	log.Printf("[+] APK Base: %s", apkpathbase)

	file_size, err_fsize := os.Stat(apkpath)
	if err_fsize != nil {
		log.Fatal(err_fsize)
	}
	bytes := file_size.Size()
	kilobytes := float32((bytes / 1024))
	megabytes := float32((kilobytes / 1024))
	log.Println("[+] APK Size:", megabytes, "MB")

	apkpathdir := filepath.Dir(apkpath) + "/"
	log.Printf("[+] APK Directory: %s", apkpathdir)
	ext := filepath.Ext(apkpathbase)
	apkname := strings.TrimSuffix(apkpathbase, ext)

	is_alphanumeric := regexp.MustCompile(`^[a-zA-Z0-9_-]*$`).MatchString(apkname)
	if !is_alphanumeric {
		log.Println("[!] Only Alphanumeric string with/without underscore/dash is accepted as APK file-name. Request you to rename the APK file.")
		os.Exit(0)
	}

	apkoutpath := apkpathdir + apkname
	dex2jarpath := apkoutpath + ".jar"
	jadxpath := apkoutpath + "_SAST/"
	log.Printf("[+] APK Static Analysis Path: %s\n", jadxpath)

	file_hash, err_fhash := ioutil.ReadFile(apkpath)
	if err_fhash != nil {
		log.Fatal(err_fhash)
	}
	log.Printf("[+] APK Hash: MD5: %x\n", md5.Sum(file_hash))
	log.Printf("[+] APK Hash: SHA256: %x\n", sha256.Sum256(file_hash))

	fmt.Printf(string(colorBlue))
	log.Println("\n[+] d2j-dex2jar has started converting APK to Java JAR file")
	fmt.Printf(string(colorReset))
	log.Println("[+] =======================================================")
	cmd_apk_dex2jar, err := exec.Command("d2j-dex2jar", apkpath, "-f", "-o", dex2jarpath).CombinedOutput()
	if err != nil {
		log.Println(err.Error())
	}
	cmd_apk_dex2jar_output := string(cmd_apk_dex2jar[:])
	log.Println("   ", cmd_apk_dex2jar_output)

	fmt.Printf(string(colorBlue))
	log.Println("[+] Jadx has started decompiling the application")
	fmt.Printf(string(colorReset))
	log.Println("[+] ============================================")
	cmd_apk_jadx, err := exec.Command("jadx", "--deobf", apkpath, "-d", jadxpath).CombinedOutput()
	if err != nil {
		log.Println(err.Error())
	}
	cmd_apk_jadx_output := string(cmd_apk_jadx[:])
	log.Println(cmd_apk_jadx_output)

	and_manifest_path := jadxpath + "resources/AndroidManifest.xml"
	fmt.Printf(string(colorBlue))
	log.Println("[+] Capturing the data from the AndroidManifest file")
	fmt.Printf(string(colorReset))
	log.Println("[+] ================================================")
	//fmt.Println(and_manifest_path)

	fmt.Printf(string(colorPurple))
	log.Println("\n==>> The Basic Information...\n")
	fmt.Printf(string(colorReset))
	// AndroidManifest file - Package name

	cmd_and_pkg_nm, err := exec.Command("grep", "-i", "package", and_manifest_path).CombinedOutput()
	if err != nil {
		log.Println("    - Package Name has not been observed.")
	}
	cmd_and_pkg_nm_output := string(cmd_and_pkg_nm[:])
	cmd_and_pkg_nm_regex := regexp.MustCompile(`package=".*?"`)
	cmd_and_pkg_nm_regex_match := cmd_and_pkg_nm_regex.FindString(cmd_and_pkg_nm_output)
	log.Println("   ", cmd_and_pkg_nm_regex_match)

	//AndroidManifest file - Package version number
	cmd_and_pkg_ver, err := exec.Command("grep", "-i", "versionName", and_manifest_path).CombinedOutput()
	if err != nil {
		log.Println("    - android:versionName has not been observed.")
	}
	cmd_and_pkg_ver_output := string(cmd_and_pkg_ver[:])
	cmd_and_pkg_ver_regex := regexp.MustCompile(`versionName=".*?"`)
	cmd_and_pkg_ver_regex_match := cmd_and_pkg_ver_regex.FindString(cmd_and_pkg_ver_output)
	log.Println("   ", cmd_and_pkg_ver_regex_match)

	//AndroidManifest file - minSdkVersion
	cmd_and_pkg_minSdkVersion, err := exec.Command("grep", "-i", "minSdkVersion", and_manifest_path).CombinedOutput()
	if err != nil {
		log.Println("    - android:minSdkVersion has not been observed.")
	}
	cmd_and_pkg_minSdkVersion_output := string(cmd_and_pkg_minSdkVersion[:])
	cmd_and_pkg_minSdkVersion_regex := regexp.MustCompile(`minSdkVersion=".*?"`)
	cmd_and_pkg_minSdkVersion_regex_match := cmd_and_pkg_minSdkVersion_regex.FindString(cmd_and_pkg_minSdkVersion_output)
	log.Println("   ", cmd_and_pkg_minSdkVersion_regex_match)

	//AndroidManifest file - targetSdkVersion
	cmd_and_pkg_targetSdkVersion, err := exec.Command("grep", "-i", "targetSdkVersion", and_manifest_path).CombinedOutput()
	if err != nil {
		log.Println("    - android:targetSdkVersion has not been observed.")
	}
	cmd_and_pkg_targetSdkVersion_output := string(cmd_and_pkg_targetSdkVersion[:])
	cmd_and_pkg_targetSdkVersion_regex := regexp.MustCompile(`targetSdkVersion=".*?"`)
	cmd_and_pkg_targetSdkVersion_regex_match := cmd_and_pkg_targetSdkVersion_regex.FindString(cmd_and_pkg_targetSdkVersion_output)
	log.Println("   ", cmd_and_pkg_targetSdkVersion_regex_match)

	//AndroidManifest file - android:networkSecurityConfig="@xml/
	cmd_and_pkg_nwSecConf, err := exec.Command("grep", "-i", "android:networkSecurityConfig=", and_manifest_path).CombinedOutput()
	if err != nil {
		log.Println("    - android:networkSecurityConfig attribute has not been observed.")
	}
	cmd_and_pkg_nwSecConf_output := string(cmd_and_pkg_nwSecConf[:])
	cmd_and_pkg_nwSecConf_regex := regexp.MustCompile(`android:networkSecurityConfig="@xml/.*?"`)
	cmd_and_pkg_nwSecConf_regex_match := cmd_and_pkg_nwSecConf_regex.FindString(cmd_and_pkg_nwSecConf_output)
	log.Println("   ", cmd_and_pkg_nwSecConf_regex_match)

	// AndroidManifest file - Activities
	fmt.Printf(string(colorPurple))
	log.Println("\n==>> The Activities...\n")
	fmt.Printf(string(colorReset))
	cmd_and_actv, err := exec.Command("grep", "-ne", "<activity", and_manifest_path).CombinedOutput()
	if err != nil {
		log.Println("- No activities have been observed")
	}
	cmd_and_actv_output := string(cmd_and_actv[:])
	log.Println(cmd_and_actv_output)
	// AndroidManifest file - Exported Activities
	exp_actv1 := `grep -ne '<activity' `
	exp_actv2 := ` | grep -e 'android:exported="true"'`
	exp_actv := exp_actv1 + and_manifest_path + exp_actv2
	log.Printf("[+] Looking for the Exported Activities specifically...\n\n")
	cmd_and_exp_actv, err := exec.Command("bash", "-c", exp_actv).CombinedOutput()
	if err != nil {
		log.Printf("\t- No exported activities have been observed.")
	}
	cmd_and_exp_actv_output := string(cmd_and_exp_actv[:])
	log.Println(cmd_and_exp_actv_output)
	cmd_and_exp_actv_output_count := strings.Count(cmd_and_exp_actv_output, `android:exported="true"`)
	log.Println("    > Total exported activities are:", cmd_and_exp_actv_output_count)
	log.Printf("\n    > QuickNote: It is recommended to use exported activities securely, if observed.\n")

	// AndroidManifest file - Content Providers
	fmt.Printf(string(colorPurple))
	log.Println("\n==>> The Content Providers...\n")
	fmt.Printf(string(colorReset))
	cmd_and_cont, err := exec.Command("grep", "-ne", "<provider", and_manifest_path).CombinedOutput()
	if err != nil {
		log.Println("\t- No Content Providers have been observed")
	}
	cmd_and_cont_output := string(cmd_and_cont[:])
	log.Println(cmd_and_cont_output)
	// AndroidManifest file - Exported Content Providers
	exp_cont1 := `grep -ne '<provider' `
	exp_cont2 := ` | grep -e 'android:exported="true"'`
	exp_cont := exp_cont1 + and_manifest_path + exp_cont2
	log.Printf("[+] Looking for the Exported Content Providers specifically...\n\n")
	cmd_and_exp_cont, err := exec.Command("bash", "-c", exp_cont).CombinedOutput()
	if err != nil {
		log.Printf("\t- No exported Content Providers have been observed.")
	}
	cmd_and_exp_cont_output := string(cmd_and_exp_cont[:])
	log.Println(cmd_and_exp_cont_output)
	cmd_and_exp_cont_output_count := strings.Count(cmd_and_exp_cont_output, `android:exported="true"`)
	log.Println("    > Total exported Content Providers are:", cmd_and_exp_cont_output_count)
	log.Printf("\n    > QuickNote: It is recommended to use exported Content Providers securely, if observed.\n")

	// AndroidManifest file - Brodcast Receivers
	fmt.Printf(string(colorPurple))
	log.Println("\n==>> The Brodcast Receivers...\n")
	fmt.Printf(string(colorReset))
	cmd_and_brod, err := exec.Command("grep", "-ne", "<receiver", and_manifest_path).CombinedOutput()
	if err != nil {
		log.Println("\t- No Brodcast Receivers have been observed.")
	}
	cmd_and_brod_output := string(cmd_and_brod[:])
	log.Println(cmd_and_brod_output)
	// AndroidManifest file - Exported Brodcast Receivers
	exp_brod1 := `grep -ne '<receiver' `
	exp_brod2 := ` | grep -e 'android:exported="true"'`
	exp_brod := exp_brod1 + and_manifest_path + exp_brod2
	log.Printf("[+] Looking for the Exported Brodcast Receivers specifically...\n\n")
	cmd_and_exp_brod, err := exec.Command("bash", "-c", exp_brod).CombinedOutput()
	if err != nil {
		log.Printf("\t- No exported Brodcast Receivers have been observed.")
	}
	cmd_and_exp_brod_output := string(cmd_and_exp_brod[:])
	log.Println(cmd_and_exp_brod_output)
	cmd_and_exp_brod_output_count := strings.Count(cmd_and_exp_brod_output, `android:exported="true"`)
	log.Println("    > Total exported Brodcast Receivers are:", cmd_and_exp_brod_output_count)
	log.Printf("\n    > QuickNote: It is recommended to use exported Brodcast Receivers securely, if observed.\n")

	// AndroidManifest file - Services
	fmt.Printf(string(colorPurple))
	log.Println("\n==>>  The Services...\n")
	fmt.Printf(string(colorReset))
	cmd_and_serv, err := exec.Command("grep", "-ne", "<service", and_manifest_path).CombinedOutput()
	if err != nil {
		log.Println("\t- No Services have been observed.")
	}
	cmd_and_serv_output := string(cmd_and_serv[:])
	log.Println(cmd_and_serv_output)
	// AndroidManifest file - Exported Services
	exp_serv1 := `grep -ne '<service' `
	exp_serv2 := ` | grep -e 'android:exported="true"'`
	exp_serv := exp_serv1 + and_manifest_path + exp_serv2
	log.Printf("[+] Looking for the Exported Services specifically...\n\n")
	cmd_and_exp_serv, err := exec.Command("bash", "-c", exp_serv).CombinedOutput()
	if err != nil {
		log.Printf("\t- No exported Services have been observed.")
	}
	cmd_and_exp_serv_output := string(cmd_and_exp_serv[:])
	log.Println(cmd_and_exp_serv_output)
	cmd_and_exp_serv_output_count := strings.Count(cmd_and_exp_serv_output, `android:exported="true"`)
	log.Println("    > Total exported Services are:", cmd_and_exp_serv_output_count)
	log.Printf("\n    > QuickNote: It is recommended to use exported Services securely, if observed.\n")

	// AndroidManifest file - Intent Filters
	fmt.Printf(string(colorPurple))
	log.Println("\n==>>  The Intents Filters...\n")
	fmt.Printf(string(colorReset))
	cmd_and_intentFilters, err := exec.Command("grep", "-ne", "android.intent.", and_manifest_path).CombinedOutput()
	if err != nil {
		log.Println("\t- No Intents Filters have been observed.")
	}
	cmd_and_intentFilters_output := string(cmd_and_intentFilters[:])
	log.Println(cmd_and_intentFilters_output)
	log.Printf("    > QuickNote: It is recommended to use Intent Filters securely, if observed.\n")

	// APK Component Summary
	fmt.Printf(string(colorBrown))
	log.Println("\n==>> APK Component Summary")
	fmt.Printf(string(colorReset))
	log.Println("[+] --------------------------------")
	log.Println("    Exported Activities:", cmd_and_exp_actv_output_count)
	log.Println("    Exported Content Providers:", cmd_and_exp_cont_output_count)
	log.Println("    Exported Broadcast Receivers:", cmd_and_exp_brod_output_count)
	log.Println("    Exported Services:", cmd_and_exp_serv_output_count)

	// SAST - Recursive file reading
	globpath := jadxpath + "sources/"
	globpath_res := jadxpath + "resources/"
	log.Printf("\n")
	fmt.Printf(string(colorCyanBold))
	log.Println(`[+] Let's start the static assessment based on "OWASP MASVS"`)
	fmt.Printf(string(colorReset))
	fmt.Println("[+] ========================================================")
	// Read .java files - /sources folder
	var files []string
	err_globpath := filepath.Walk(globpath, func(path string, info os.FileInfo, err error) error {
		files = append(files, path)
		return nil
	})
	if err_globpath != nil {
		panic(err_globpath)
	}
	// Read .xml files - /resources folder
	var files_res []string
	err_globpath_res := filepath.Walk(globpath_res, func(path string, info os.FileInfo, err error) error {
		files_res = append(files_res, path)
		return nil
	})
	if err_globpath_res != nil {
		panic(err_globpath_res)
	}

	// OWASP MASVS - V2: Data Storage and Privacy Requirements
	log.Printf("\n")
	fmt.Printf(string(colorBlueBold))
	log.Println(`[+] Hunting begins based on "V2: Data Storage and Privacy Requirements"`)
	fmt.Printf(string(colorReset))
	log.Println("[+] -------------------------------------------------------------------")

	// // MASVS V2 - MSTG-STORAGE-14 - Possible Hard-coded Keys/Tokens/Secrets
	// fmt.Printf(string(colorPurple))
	// log.Println("\n==>> The potential Hard-coded Keys/Tokens/Secrets...\n")
	// fmt.Printf(string(colorReset))
	// var countHardcodedKeys = 0
	// for _, sources_file := range files_res {
	// 	if filepath.Ext(sources_file) == ".xml" {
	// 		cmd_and_pkg_hardcodedKeys, err := exec.Command("grep", "-nri", "-E", `(_key"|_secret"|_token"|_client_id"|_api"|_debug"|_prod"|_stage"|_BASE_URL"|_URL"|http:|http://)`, "--include", `*.xml`, sources_file).CombinedOutput()
	// 		if err != nil {
	// 			//fmt.Println("- Possible Hard-coded Keys/Tokens have not been observed")
	// 		}
	// 		cmd_and_pkg_hardcodedKeys_output := string(cmd_and_pkg_hardcodedKeys[:])
	// 		if strings.Contains(cmd_and_pkg_hardcodedKeys_output, "_key") || strings.Contains(cmd_and_pkg_hardcodedKeys_output, "_secret") || strings.Contains(cmd_and_pkg_hardcodedKeys_output, "_token") || strings.Contains(cmd_and_pkg_hardcodedKeys_output, "_client_id") || strings.Contains(cmd_and_pkg_hardcodedKeys_output, "_api") || strings.Contains(cmd_and_pkg_hardcodedKeys_output, "_debug") || strings.Contains(cmd_and_pkg_hardcodedKeys_output, "_prod") || strings.Contains(cmd_and_pkg_hardcodedKeys_output, "_stage") || strings.Contains(cmd_and_pkg_hardcodedKeys_output, "_BASE_URL") || strings.Contains(cmd_and_pkg_hardcodedKeys_output, "_URL") || strings.Contains(cmd_and_pkg_hardcodedKeys_output, "http:") || strings.Contains(cmd_and_pkg_hardcodedKeys_output, "http://") {
	// 			fmt.Printf(string(colorBrown))
	// 			log.Println(sources_file)
	// 			fmt.Printf(string(colorReset))
	// 			log.Println(cmd_and_pkg_hardcodedKeys_output)
	// 			countHardcodedKeys++
	// 		}
	// 	}
	// }
	// if int(countHardcodedKeys) > 0 {
	// 	fmt.Printf(string(colorCyan))
	// 	log.Printf("[!] QuickNote:")
	// 	fmt.Printf(string(colorReset))
	// 	log.Printf("    - It is recommended that the hard-coded keys/tokens/secrets should not be stored unless secured specifically, if observed. Please note that, an attacker can use that data for further malicious intentions.")
	// 	fmt.Printf(string(colorCyan))
	// 	log.Printf("\n[*] Reference:")
	// 	fmt.Printf(string(colorReset))
	// 	log.Printf("    - OWASP MASVS: MSTG-STORAGE-14 | CWE-312: Cleartext Storage of Sensitive Information")
	// 	log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")
	// }

	// MASVS V2 - MSTG-STORAGE-14 - Possible Hard-coded Keys/Tokens/Secrets
	fmt.Printf(string(colorPurple))
	log.Println("\n==>> The potential Hard-coded Keys/Tokens/Secrets...\n")
	fmt.Printf(string(colorReset))

	var countHardcodedKeys = 0
	for _, sources_file := range files_res {
		// Check if the current file is strings.xml
		if filepath.Base(sources_file) == "strings.xml" {
			cmd_and_pkg_hardcodedKeys, err := exec.Command("grep", "-nri", "-E", `(_key"|_secret"|_token"|_client_id"|_api"|_debug"|_prod"|_stage"|_BASE_URL"|_URL"|http:|http://)`, sources_file).CombinedOutput()
			if err != nil {
				// Handle the error
			}
			cmd_and_pkg_hardcodedKeys_output := string(cmd_and_pkg_hardcodedKeys[:])
			if strings.Contains(cmd_and_pkg_hardcodedKeys_output, "_key") || strings.Contains(cmd_and_pkg_hardcodedKeys_output, "_secret") || strings.Contains(cmd_and_pkg_hardcodedKeys_output, "_token") || strings.Contains(cmd_and_pkg_hardcodedKeys_output, "_client_id") || strings.Contains(cmd_and_pkg_hardcodedKeys_output, "_api") || strings.Contains(cmd_and_pkg_hardcodedKeys_output, "_debug") || strings.Contains(cmd_and_pkg_hardcodedKeys_output, "_prod") || strings.Contains(cmd_and_pkg_hardcodedKeys_output, "_stage") || strings.Contains(cmd_and_pkg_hardcodedKeys_output, "_BASE_URL") || strings.Contains(cmd_and_pkg_hardcodedKeys_output, "_URL") || strings.Contains(cmd_and_pkg_hardcodedKeys_output, "http:") || strings.Contains(cmd_and_pkg_hardcodedKeys_output, "http://") {
				fmt.Printf(string(colorBrown))
				log.Println(sources_file)
				fmt.Printf(string(colorReset))
				log.Println(cmd_and_pkg_hardcodedKeys_output)
				countHardcodedKeys++
			}
		}
	}

	if int(countHardcodedKeys) > 0 {
		fmt.Printf(string(colorCyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(colorReset))
		log.Printf("    - It is recommended that the hard-coded keys/tokens/secrets should not be stored unless secured specifically, if observed. Please note that, an attacker can use that data for further malicious intentions.")
		fmt.Printf(string(colorCyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(colorReset))
		log.Printf("    - OWASP MASVS: MSTG-STORAGE-14 | CWE-312: Cleartext Storage of Sensitive Information")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")
	}

	// OWASP MASVS - V5: Network Communication Requirements
	log.Println("\n")
	fmt.Printf(string(colorBlueBold))
	log.Println(`[+] Hunting begins based on "V5: Network Communication Requirements"`)
	fmt.Printf(string(colorReset))
	log.Println("[+] ----------------------------------------------------------------")

	// MASVS V5 - MSTG-NETWORK-1 - Possible MITM attack
	fmt.Printf(string(colorPurple))
	log.Println("\n==>> The Possible MITM attack...\n")
	fmt.Printf(string(colorReset))

	var countHTTP = 0
	for _, sources_file := range files {
		ext := filepath.Ext(sources_file)
		if ext == ".java" || ext == ".kt" {
			// Check if the current file is RetrofitClient.java
			if filepath.Base(sources_file) == "RetrofitClient.java" {
				cmd_and_pkg_unencryptedProtocol, err := exec.Command("grep", "-nri", "-e", "http:", sources_file).CombinedOutput()
				if err != nil {
					// Handle the error
				}
				cmd_and_pkg_unencryptedProtocol_output := string(cmd_and_pkg_unencryptedProtocol[:])
				// Check if the found http: is not followed by 's'
				if strings.Contains(cmd_and_pkg_unencryptedProtocol_output, "http:") && !strings.Contains(cmd_and_pkg_unencryptedProtocol_output, "https:") || strings.Contains(cmd_and_pkg_unencryptedProtocol_output, "getInsecure") {
					fmt.Printf(string(colorBrown))
					log.Println(sources_file)
					fmt.Printf(string(colorReset))
					log.Println(cmd_and_pkg_unencryptedProtocol_output)
					countHTTP++
				}
			}
		}
	}

	if int(countHTTP) > 0 {
		fmt.Printf(string(colorCyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(colorReset))
		log.Printf("    - It is recommended not to use any unencrypted transmission mechanisms for sensitive data. Please note that, the HTTP protocol does not provide any encryption of the transmitted data, which can be easily intercepted by an attacker.")
		fmt.Printf(string(colorCyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(colorReset))
		log.Printf("    - OWASP MASVS: MSTG-NETWORK-1 | CWE-319: Cleartext Transmission of Sensitive Information")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x10-v5-network_communication_requirements")
	}

	// OWASP MASVS - V6: Platform Interaction Requirements
	log.Println("\n")
	fmt.Printf(string(colorBlueBold))
	log.Println(`[+] Hunting begins based on "V6: Platform Interaction Requirements"`)
	fmt.Printf(string(colorReset))
	log.Println("[+] ---------------------------------------------------------------")

	// MASVS V6 - MSTG-PLATFORM-2 - potential SQL Injection
	fmt.Printf(string(colorPurple))
	log.Println("\n==>> The potential SQL Injection instances...\n")
	fmt.Printf(string(colorReset))
	var countSqli = 0
	for _, sources_file := range files {
		if filepath.Ext(sources_file) == ".java" {
			cmd_and_pkg_sqli, err := exec.Command("grep", "-nr", "-e", ".rawQuery(", "-e", "appendWhere(", sources_file).CombinedOutput()
			if err != nil {
				//fmt.Println("- potential SQL Injection instances have not been observed")
			}
			cmd_and_pkg_sqli_output := string(cmd_and_pkg_sqli[:])
			if (strings.Contains(cmd_and_pkg_sqli_output, ".rawQuery(")) || (strings.Contains(cmd_and_pkg_sqli_output, ".execSQL(")) || (strings.Contains(cmd_and_pkg_sqli_output, ".appendWhere(")) {
				fmt.Printf(string(colorBrown))
				log.Println(sources_file)
				fmt.Printf(string(colorReset))
				log.Println(cmd_and_pkg_sqli_output)
				countSqli++
			}
		}
	}
	if int(countSqli) > 0 {
		fmt.Printf(string(colorCyan))
		log.Printf("[!] QuickNote:")
		fmt.Printf(string(colorReset))
		log.Printf("    - It is recommended that Prepared Statements are used or methods have been used securely to perform any sensitive tasks related to the databases, if observed.")
		fmt.Printf(string(colorCyan))
		log.Printf("\n[*] Reference:")
		fmt.Printf(string(colorReset))
		log.Printf("    - OWASP MASVS: MSTG-PLATFORM-2 | CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')")
		log.Printf("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x11-v6-interaction_with_the_environment")
	}

}
