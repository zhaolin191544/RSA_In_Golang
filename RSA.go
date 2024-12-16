package main

import (
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"math/big"
)

func generateKeys(bitSize int, e *big.Int) (d, n *big.Int, err error) { //2022220036 赵麟
	//随机生成两个大素数
	p, err := rand.Prime(rand.Reader, bitSize)
	if err != nil {
		return nil, nil, err
	}
	q, err := rand.Prime(rand.Reader, bitSize)
	if err != nil {
		return nil, nil, err
	}

	//计算n
	n = new(big.Int).Mul(p, q)

	//计算φ(n)
	phi := new(big.Int).Mul(
		new(big.Int).Sub(p, big.NewInt(1)),
		new(big.Int).Sub(q, big.NewInt(1)),
	)

	//确保e与φ(n)互质
	gcd := new(big.Int).GCD(nil, nil, e, phi)
	if gcd.Cmp(big.NewInt(1)) != 0 {
		return nil, nil, fmt.Errorf("e 与 φ(n) 不互质")
	}

	//计算d，使得d*e≡1 mod φ(n)
	d = new(big.Int).ModInverse(e, phi)
	if d == nil {
		return nil, nil, fmt.Errorf("无法计算 d 的逆元")
	}

	return d, n, nil
}

// RSA 加密函数：cipherText = message^e mod n
func rsaEncrypt(message, e, n *big.Int) *big.Int {
	cipherText := new(big.Int).Exp(message, e, n)
	return cipherText
}

// RSA 解密函数：message = cipherText^d mod n
func rsaDecrypt(cipherText, d, n *big.Int) *big.Int {
	message := new(big.Int).Exp(cipherText, d, n)
	return message
}

/*
func main() {
	//设置密钥参数
	bitSize := 512         // 密钥位数，实际应用中至少应为 2048 位
	e := big.NewInt(65537) // 公钥指数，常用值为 3、17、65537

	//生成RSA密钥对
	d, n, err := generateKeys(bitSize, e)
	if err != nil {
		fmt.Println("密钥生成失败：", err)
		return
	}

	//输出密钥对
	fmt.Println("公钥 (e, n)：")
	fmt.Println("e =", e)
	fmt.Println("n =", n)
	fmt.Println("\n私钥 d：")
	fmt.Println("d =", d)

	//原始消息
	message := big.NewInt(2022220036) //学号 2022220036 赵麟
	fmt.Println("\n原始消息：", message)

	//加密消息
	cipherText := encrypt(message, e, n)
	fmt.Println("\n加密后的密文：", cipherText)

	//解密消息
	decryptedMessage := decrypt(cipherText, d, n)
	fmt.Println("\n解密后的消息：", decryptedMessage)
}*/

func main() {
	// 设置密钥参数
	bitSize := 8192        // 增大密钥位数，以支持更长的加密内容
	e := big.NewInt(65537) // 公钥指数，常用值为 3、17、65537

	// 生成 RSA 密钥对
	d, n, err := generateKeys(bitSize, e)
	if err != nil {
		fmt.Println("密钥生成失败：", err)
		return
	}

	// 输出密钥对（为了安全，实际应用中不要打印私钥）
	fmt.Println("公钥 (e, n)：")
	fmt.Println("e =", e)
	// fmt.Println("n =", n) // n 可能非常大，打印会影响阅读

	fmt.Println("\n私钥 d：")
	// fmt.Println("d =", d) // d 可能非常大，打印会影响阅读

	// 读取 plain.txt 文件内容
	plainBytes, err := ioutil.ReadFile("test1.txt")
	if err != nil {
		fmt.Println("读取文件失败：", err)
		return
	}
	fmt.Println("\n原始内容：")
	fmt.Println(string(plainBytes))

	// 将文件内容转换为大整数形式
	messageInt := new(big.Int).SetBytes(plainBytes)

	// 检查消息是否小于模数 n
	if messageInt.Cmp(n) >= 0 {
		fmt.Println("错误：消息过长，无法加密。请增大密钥位数或减少消息长度。")
		return
	}

	// 使用 RSA 加密消息
	cipherInt := rsaEncrypt(messageInt, e, n)
	fmt.Println("\n加密后的密文（大整数表示）：")
	// fmt.Println(cipherInt) // 密文可能非常大，打印会影响阅读

	// 将密文保存到文件（以便查看或进一步处理）
	err = ioutil.WriteFile("cipher.txt", cipherInt.Bytes(), 0644)
	if err != nil {
		fmt.Println("保存密文失败：", err)
		return
	}
	fmt.Println("密文已保存到 cipher.txt 文件。")

	// 使用 RSA 解密密文
	decryptedInt := rsaDecrypt(cipherInt, d, n)

	// 将解密后的大整数转换回字节数组
	decryptedBytes := decryptedInt.Bytes()

	// 将解密后的字节数组写入文件
	err = ioutil.WriteFile("decrypted.txt", decryptedBytes, 0644)
	if err != nil {
		fmt.Println("保存解密后的内容失败：", err)
		return
	}

	fmt.Println("\n解密后的内容：")
	fmt.Println(string(decryptedBytes))
}
