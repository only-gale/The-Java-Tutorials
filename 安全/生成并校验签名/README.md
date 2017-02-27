> #### 这部分将向你阐明使用JDK Security API生成一个数字签名和校验一个签名是否可信的必要步骤。
> #### 为此你将会创建两个基本的应用程序，一个用于生成数字签名，另一个用于校验数字签名。

- [生成一个数字签名](#生成一个数字签名)
- [校验一个数字签名](#校验一个数字签名)
- [缺陷和解决方案](#缺陷和解决方案)

## 生成一个数字签名

- [准备初始结构](#准备初始结构)
- [生成公钥和私钥](#生成公钥和私钥)
- [签署数据](#签署数据)
- [保存签名和公钥](#保存签名和公钥)
- [编译运行](#编译运行)

#### 准备初始结构
_创建GenSig.java，输入初始程序结构（例如：import语句，类名，main方法）_

```java
import java.io.*;
import java.security.*;

class GenSig {

    public static void main(String[] args) {

        /* Generate a DSA signature */

        if (args.length != 1) {
            System.out.println("Usage: GenSig nameOfFileToSign");
        }
        else try {

        // the rest of the code goes here

        } catch (Exception e) {
            System.err.println("Caught exception " + e.toString());
        }
    }
}
```

注：
   * 由于签名的方法都在`java.security`包里，所以上面的代码导入了整个包。代码还导入了`java.io`包，是为了从文件中读取签名数据。
   * 该程序将需要一个参数，指定用于签名的数据文件。
   * 后续将要写的代码都会放进上面代码里的`try catch`块。

#### 生成公钥和私钥
为了生成一个数字签名，我们需要一个私钥。（它所对应的公钥是用来校验签名的。）

在密钥对（私钥和公钥）已存在的情况下，只需要导入私钥即可。否则，我们需要利用`KeyPairGenerator`类生成密钥对。

在本例中，我们将生成一个长度为1024位的DSA（Digital Signature Algorithm）密钥对。步骤如下：

   1. 创建密钥对生成器
  
      第一步是获取一个DSA密钥对生成器对象。
  
      在Java中，获取一个`KeyPairGenerator`对象的共有方式，是调用它的静态方法`getInstance`。
      这个方法有两种形式，一种只有一个`(String algorithm)`参数，另一种有两个参数`(String algorithm, String provider)`。
  
      参数`String provider`将保证算法（由参数`String algorithm`指定）实现的来源，比如指定为`SUN`，则算法实现来源于JDK。本例中我们将其指定为`SUN`。

      ```java
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");
      ```

   2. 初始化密钥对生成器

      第二步是初始化密钥对生成器。在Java中，所有的密钥对生成器都建立在密钥长度和随机数的概念之上。对于`KeyPairGenerator`，它有一个`initialize`方法来初始化这两个参数。
  
      在本例中，密钥长度将被设置为**1024**.
  
      需要说明的是，随机数必须是`SecureRandom`类的实例，因为它提供了一个强加密的随机数生成器。
  
      下面的代码获取了一个使用了SHA1PRNG算法的`SecureRandom`实例，该算法也被设置为来源于JDK。
  
      ```java
      SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
      keyGen.initialize(1024, random);
      ```
  
      值得注意的是，有些情况要求强随机数，比如创建RSA算法的密钥对。为了指导程序选择合适的 `SecureRandom`实现类，从**JDK8**开始，`java.security.Security`类
      的属性 `securerandom.strongAlgorithms`里包含了一系列已知的强`SecureRandom`实现，可以通过 `java.security.Security.getProperty( "securerandom.strongAlgorithms" )`来查看。
      所以当你需要创建一个强`SecureRandom`的对象时，应该考虑调用 `SecureRandom.getInstanceStrong()`。
  
   3. 生成密钥对

      最后一步是生成密钥对，并保存密钥到`PrivateKey`和`PublicKey`对象中。
  
      ```java
      KeyPair pair = keyGen.generateKeyPair();
      PrivateKey priv = pair.getPrivate();
      PublicKey pub = pair.getPublic();
      ```
  
#### 签署数据
到现在为止，你已经拥有了密钥对，准备签署数据吧。在本例中，你将签署的数据保存在一个文件中。程序GenSig从命令行获取这个文件名。一个数字签名是用`Signature`的实例来创建的。
整个过程的步骤如下：

   1. 获取`Signature`对象
      
      下面的代码将得到一个由JDK内嵌的DSA算法实现的数字签名，算法和提供者必须和之前生成密钥对时使用的一致。
      
      ```java
      Signature dsa = Signature.getInstance("SHA1withDSA", "SUN");
      ```
      
      **注意**：在指定数字签名的算法名称时，你还得指定此签名算法所使用的消息摘要算法的名字。上面代码中的`SHA1withDSA`就是用来指定使用了SHA-1消息摘要算法的DSA签名算法的一种方式。
      
   2. 初始化`Signature`对象
   
      在一个`Signature`对象可以被用来签名或者校验之前，它必须被初始化。用于签名的初始化方法需要指定一个私钥。在这里，我们使用之前创建的`PrivateKey`类对象priv。
      
      ```java
      dsa.initSign(priv);
      ```
   
   3. 提供数据给`Signature`对象
   
      下面的代码将从命令行指定的文件里读取数据并提供给`Signature`对象dsa：
      
      ```java
      FileInputStream fis = new FileInputStream(args[0]);
      BufferedInputStream bufin = new BufferedInputStream(fis);
      byte[] buffer = new byte[1024];
      int len;
      while ((len = bufin.read(buffer)) >= 0) {
          dsa.update(buffer, 0, len);
      };
      bufin.close();
      ```
      
   4. 生成签名
   
      一旦将所有数据提供给`Signature`对象dsa，你就可以生成对应于那些数据的唯一数字签名。
      
      ```java
      byte[] realSig = dsa.sign();
      ```

#### 保存签名和公钥
现在你已经为一些数据生成了一个数字签名，你需要将签名字节码保存在一个文件里，将公钥字节码保存在另一个文件里，以便发给其他人。

可以通过下面的代码_将`realSig`保存到名为sig的文件中：_

```java
/* save the signature in a file */
FileOutputStream sigfos = new FileOutputStream("sig");
sigfos.write(realSig);
sigfos.close();
```

可以通过下面的代码_将公钥保存在一个文件里_：

```java
/* save the public key in a file */
byte[] key = pub.getEncoded();      // 获取字节码
FileOutputStream keyfos = new FileOutputStream("suepk");        // 文件名可以是任何你想要的名字
keyfos.write(key);
keyfos.close();
```

我们将在[校验一个数字签名](#校验一个数字签名)部分里创建一个名为VerSig的程序，（你所发送的数据的）接受者可以运行此程序来验证他所接收到的数据在传输过程中没有被改变过。
VerSig是利用你发送给它的公钥来验证接收到的签名是不是真正的对应于它收到的数据的签名。

#### 编译运行
到目前为止，我们已经完成了[GenSig.java](http://docs.oracle.com/javase/tutorial/security/apisign/examples/GenSig.java)的编写。现在你可以编译并运行它。
如果你有一些数据保存在一个名为data的文件中，那么你将可以用以下命令来运行：

`java GenSig data`

当运行结束后，你应该可以看到生成的suepk文件（里面保存的是public key）和sig文件（里面保存的是签名）。

## 校验一个数字签名
如果你有生成签名时所用的数据，那么你就可以校验签名的认证信息。具体你需要这些东西：

* 数据
* 签名
* 用于签名数据的私钥的对应公钥

在本例中，你将编写一个名为VerSig的程序去校验之前的GenSig程序生成的签名。

VerSig将会导入一个公钥和一个被称之为是指定文件的签名，然后验证这个签名的认证信息。公钥、签名和文件名将会在命令行里提供。
具体步骤如下：

- [准备初始结构](#准备初始结构)
- [输入并转化公钥字节码](#输入并转化公钥字节码)
- [输入签名字节码](#输入签名字节码)
- [校验签名](#校验签名)
- [编译运行](#编译运行)

#### 准备初始结构
_创建VerSig.java，输入初始程序结构（例如：import语句，类名，main方法）_

```java
import java.io.*;
import java.security.*;
import java.security.spec.*;

class VerSig {

    public static void main(String[] args) {

        /* Verify a DSA signature */

        if (args.length != 3) {
            System.out.println("Usage: VerSig " +
                "publickeyfile signaturefile " + "datafile");
        }
        else try {

        // the rest of the code goes here

        } catch (Exception e) {
            System.err.println("Caught exception " + e.toString());
        }
    }

}
```

注：
   * 由于签名的方法都在`java.security`包里，所以上面的代码导入了整个包。代码还导入了`java.io`包，是为了从文件中读取签名数据。
     还导入了`java.security.spec`包，因为它包含了`X509EncodedKeySpec`类。
   * 该程序将需要三个参数，指定公钥、签名和数据文件。
   * 后续将要写的代码都会放进上面代码里的`try catch`块

#### 输入并转化公钥字节码
接下来，VerSig需要从命令行第一个参数所指定的文件中导入已编码的公钥字节码，并将其转换成一个`PublicKey`对象，因为`Signature`类中的初始化方法`initVerify`需要的是一个`PublicKey`对象。

我们分步走，先读进已编码的公钥字节码：
```java
FileInputStream keyfis = new FileInputStream(args[0]);
byte[] encKey = new byte[keyfis.available()];  
keyfis.read(encKey);

keyfis.close();
```

接下来，我们可以用`KeyFactory`类将已编码的公钥字节码初始化成一个DSA算法实现的公钥。这个`KeyFactory`类提供了非透明的密钥及其透明的原始信息（官方称之为key specifications）之间的转换规则。
从一个密钥中，我们只能够得到实现它的算法，编码格式，以及编码后的字节码，但得不到这个密钥的原始信息，比如key本身，以及用来计算这个key的算法的相关参数。

所以呢，我们得先得到一个key specifications。假设key是根据X.509标准来编码的（本例就是，因为我们之前是利用JDK内建（提供者名为SUN）的DSA密钥对生成器生成的密钥，还记得吗？），那我们可以通过以下代码获取到：

```java
X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encKey);
```

现在我们可以使用一个`KeyFactory`对象来进行转换了，但是这个对象必须适用于DSA密钥：

```java
KeyFactory keyFactory = KeyFactory.getInstance("DSA", "SUN");
```

最后，我们就利用这个`keyFactory`对象从之前得到的那个key specifications中获取到公钥：

```java
PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);
```

#### 输入签名字节码
接下来，我们将从命令行第二个参数所指定的文件中读取数字签名：

```java
FileInputStream sigfis = new FileInputStream(args[1]);
byte[] sigToVerify = new byte[sigfis.available()]; 
sigfis.read(sigToVerify);
sigfis.close();
```

现在，这个sigToVerify字节数组中包含了数字签名的字节码。

#### 校验签名
现在重点来了，我们之前做的所有准备工作都是为了校验签名。步骤如下：

   1. 初始化签名对象
   
      和生成签名一样，校验一个签名也是用`Signature`实例。所有呢，我们需要利用和生成签名时一样的算法创建一个`Signature`对象：
      
      ```java
      Signature sig = Signature.getInstance("SHA1withDSA", "SUN");
      ```
      
      现在我们需要初始化这个对象，而用于验证的初始化方法需要指定一个公钥：
      
      ```java
      sig.initVerify(pubKey);
      ```
      
   2. 提供需要验证的数据给签名对象
      
      还记得吗？之前我们生成签名的时候是根据一些数据生成的，那现在我们验证签名的时候同样需要这些数据。这些数据被放在一个文件里，在这里，该文件名将被命令行的第三个参数指定：
      
      ```java
      FileInputStream datafis = new FileInputStream(args[2]);
      BufferedInputStream bufin = new BufferedInputStream(datafis);
      
      byte[] buffer = new byte[1024];
      int len;
      while (bufin.available() != 0) {
          len = bufin.read(buffer);
          sig.update(buffer, 0, len);
      };
      
      bufin.close();
      ```
      
   3. 验证签名
   
      一旦将全部数据提供给上述代码中创建的用于校验的签名对象sig，我们就可以开始校验并汇报校验结果了。
      
      ```java
      boolean verifies = sig.verify(sigToVerify);
      
      System.out.println("signature verifies: " + verifies);
      ```
      
      如果我们从命令行所读入的被校验签名（sigToVerify）就是当初根据私钥生成的签名，那么现在我们用根据对应的公钥生成的签名sig去验证它的时候，结果应该是true。
      
所以，到此为止，你理解整个过程了么？其实很简单，我们可以把整个过程这样解释：

我有一个全球唯一的密钥对（一个私钥及其对应的公钥）和一个文件，我希望将此文件发给你，同时希望你接收到的文件和我的文件完全一样。我们都不能控制传输过程，那怎么办呢？

首先我用我的私钥根据某一算法对这个文件中的数据生成一个唯一的数字签名，然后将文件、与我的私钥对应的那个公钥以及这个数字签名同时以文件的形式发给你。

当你收到这3个文件的时候，首先你可以直接阅读此文件（不用任何解码，因为我发送给你的时候就根本没有对其做任何编码），但是你如何知道你所接收到的这个文件是不是和我的文件完全一样呢？
那么你需要利用你同时接收到的公钥和签名来对此文件进行校验。校验过程就是你用公钥根据相同的算法（包括算法的来源也必须相同）对此文件生成另一个签名，然后拿来和你接收到的那个签名进行比较，完全一致就说明你收到的这个文件就是我当初发给你的，它并没有在传输过程中被做过任何修改。

#### 编译运行
这里有完整的[VerSig.java](http://docs.oracle.com/javase/tutorial/security/apisign/examples/VerSig.java)源码可供参考。

记住，要编译运行VerSig.java，你需要指定三个参数：

   1. 包含已编码的公钥字节码文件名
   
   2. 包含签名字节码的文件名
   
   3. 包含被验证数据的文件名

由于我们将验证的是之前的`GenSig`的输出文件，所以在这里我应该用的文件名分别是

   1. suepk
   
   2. sig
   
   3. data
   
比如这样：

   java VerSig suepk sig data

你应该可以看到结果： signature verifies: true

## 缺陷和解决方案
在这一章节中，GenSig和VerSig两个程序说明了**JDK Security API**生成和校验一个数字签名的基本用法。然而，在现实场景中，这样的用法其实有点不切实际，甚至还有一个潜在的主要缺陷。

不切实际在于，很多数情况下，我们不需要手动生成密钥对，因为它们已经以编码过的形式存在于文件中或者keystore中。

潜在的最大缺陷指的是，数据接收者接收到的公钥是否可信得不到任何保证。VerSig程序只有在提供给它的公钥是可信（与私钥对应）的时候才能够校验成功。

### 使用已编码的密钥字节码
正如之前所说，很多情况下已编码的密钥对（公钥和私钥）字节码已经分别存在于文件中。假设我们现在有一个用PKCS #8标准编码过的的DSA私钥字节码文件，并将文件名保存在`privkeyfile`字符串中，
那么，GenSig程序就可以通过以下代码导入此文件，并将里面的字节码转换成一个用于签名的私钥：

```java
FileInputStream keyfis = new FileInputStream(privkeyfile);
byte[] encKey = new byte[keyfis.available()];
keyfis.read(encKey);
keyfis.close();

PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(encKey);

KeyFactory keyFactory = KeyFactory.getInstance("DSA");
PrivateKey privKey = keyFactory.generatePrivate(privKeySpec);
```

而且，GenSig程序也不再需要将公钥字节码编码并保存到文件中，因为已经存在。

在这种情况下，发送者将发送给接收者以下文件：

   - 以存在的公钥字节码文件（除非接收者已经拥有此文件）
   - 数据文件
   - GenSig程序导出的签名文件

VerSig程序将保持不变，因为它已经是从文件中读取以编码的公钥字节码。

但是有一个潜在的问题就是，恶意攻击者以一种不能被检测到的方式拦截并替换这些文件会怎么样呢？在一些场景中，这根本不是问题。因为人们（发送者和接收者）已经面对面交换过公钥，或者通过一个可信的第三方交换。
此后，可能会远程完成各种文件和签名的交换，并且用公钥去校验这些文件的授信信息。那么这样一来，攻击者的行为将会被VerSig程序检测到。

如果无法面对面交换公钥，那我们可以尝试其他增加类似可信度的方法。

总体而言，将公钥和其他数据文件以及签名文件分开发送能够大大减少类似的攻击。除非三个文件都被改变，并且以将在下一段中讨论的方式进行。否则，VerSig将检测到任何攻击。

如果三个文件都被攻击者拦截，他可以将数据文件替换成其他文件，用另一个私钥为它签名，然后将新的文件、新的签名和新的公钥继续发送给你。这时候VerSig程序将校验成功，
你会以为收到的数据文件依然来自于原来的发送者。鉴于此，我们就应该采取措施去保证至少公钥会被完整的接收，或者我们可以用证书去简化公钥的授信，我们将在下一部分介绍。

### 使用证书
其实，加密的通常做法不是直接交换公钥本身，而是交换包含公钥和其他附加信息（比如证书签发者、过期时间等信息）的证书。

这样做的一个好处是，一个证书一般是由一个第三方实体（证书认证组织，CA）签署，去证明封闭的公钥是另一个实体（私钥的拥有者）的实际公钥。

另一个好处是，证书本身的合法性是可被校验的，我们只需要利用证书签发者的公钥去校验证书的数字签名即可。也有可能待验证的证书的公钥存在于另一个证书中，那我们就得以同样的方式去验证那个证书的可信度，这样就形成了一个信任链，只要在此链中找到了一个我们非常信任的一个（比如google），那我们就可以信任当前所接收到的证书。

如果你无法得到一个信任链（也许是因为某个证书签发者对你不可用），那么你可以计算出证书的验证码（**fingerprint(s)**）。验证码是一串相对较短的字节码，可以唯一地可靠地验证证书。
（从技术上讲，这里所说的验证码，是利用不可逆的hash函数对证书信息所计算出的一个hash值。）你可以用你计算出的验证码去向证书签发者求证。

无疑，如果我们让GenSig程序创建一个包含了公钥的证书，然后VerSig程序导入这个证书并从中拿到公钥，这样就会更安全。然而，JDK只有从证书中获取公钥的APIs，却没有相应的APIs让我们从一个公钥创建出一个证书。

如果你愿意，可以利用其他工具，而非APIs，配合keystore中的证书去签署重要的文档，正如我们在[文件交换](../文件交换/README.md)部分所做的那样。

要不然我们可以利用API修改程序，让它们可以和一个已存在的私钥及其对应的来自我们自己的keystore中的公钥（包含在证书中）一起工作。
在开始修改GenSig程序以便从keystore中获取私钥之前，我们先做一些假设：

   - keystore的名称存放在`ksName`字符串中
   - keystore的类型是Oracle专有的JKS
   - keystore的密码存放在`spass`字符数组中
   - keystore记录的别名(alias)中包含有私钥，公钥证书存放在`alias`字符串中
   - 私钥密码存放在`kpass`字符数组中

现在，可以通过以下代码从keystore中获取私钥：

   ```java
   KeyStore ks = KeyStore.getInstance("JKS");
   FileInputStream ksfis = new FileInputStream(ksName); 
   BufferedInputStream ksbufin = new BufferedInputStream(ksfis);
   
   ks.load(ksbufin, spass);
   PrivateKey priv = (PrivateKey) ks.getKey(alias, kpass);
   ```

可以通过以下代码从keystore中获取公钥证书并保存其已编码的字节码到文件suecert中：

   ```java
   java.security.cert.Certificate cert = ks.getCertificate(alias);
   byte[] encodedCert = cert.getEncoded();
   
   // Save the certificate in a file named "suecert" 
   
   FileOutputStream certfos = new FileOutputStream("suecert");
   certfos.write(encodedCert);
   certfos.close();
   ```

然后我们发送数据文件、签名文件和证书给接收者。接收者为了验证证书的授信信息，可以通过命令**keytool -printcert**来获取证书的验证码：

   ```ssh
   keytool -printcert -file suecert
   Owner: CN=Susan Jones, OU=Purchasing, O=ABC, L=Cupertino, ST=CA, C=US
   Issuer: CN=Susan Jones, OU=Purchasing, O=ABC, L=Cupertino, ST=CA, C=US
   Serial number: 35aaed17
   Valid from: Mon Jul 13 22:31:03 PDT 1998 until:
   Sun Oct 11 22:31:03 PDT 1998
   Certificate fingerprints:
   MD5:  1E:B8:04:59:86:7A:78:6B:40:AC:64:89:2C:0F:DD:13
   SHA1: 1C:79:BD:26:A1:34:C0:0A:30:63:11:6A:F2:B9:67:DF:E5:8D:7B:5E
   ```

得到了证书的验证码后，接收者可以向证书签发者求证是否有效，比如打电话给证书签发者。

证书校验成功后，接收者的校验程序（修改后的VerSig程序）可以导入证书并从中获取公钥：

   ```java
   FileInputStream certfis = new FileInputStream(certName);         // 证书文件名存放在certName字符串中
   java.security.cert.CertificateFactory cf =
       java.security.cert.CertificateFactory.getInstance("X.509");
   java.security.cert.Certificate cert =  cf.generateCertificate(certfis);
   PublicKey pub = cert.getPublicKey();
   ```

### 保证数据机密性
记住，如果你不想让其他人无意甚至恶意地在传输过程中（或者在你自己机器或硬盘中）查看你的数据，那你应该始终对这些数据加密，并且只传输加密后端结果。
