/**
 * 网络安全闯关游戏 - Cloudflare Workers 后端
 * 特性：设备指纹认证、动态flag、访客统计、无状态设计
 */

// ==================== 设备指纹和认证系统 ====================

/**
 * 生成设备指纹（基于多个维度）
 */
function generateFingerprint(request) {
  const headers = request.headers;
  const components = [
    headers.get('user-agent') || '',
    headers.get('accept-language') || '',
    headers.get('accept-encoding') || '',
    headers.get('sec-ch-ua') || '',
    headers.get('sec-ch-ua-platform') || '',
  ].join('|');

  return hashString(components);
}

/**
 * 简单哈希函数
 */
function hashString(str) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash; // Convert to 32bit integer
  }
  return Math.abs(hash).toString(16);
}

/**
 * MD5 哈希函数（简化实现）
 */
async function md5(str) {
  const encoder = new TextEncoder();
  const data = encoder.encode(str);
  const hashBuffer = await crypto.subtle.digest('MD5', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * 生成访客ID（设备指纹+IP+时间戳）
 */
function generateVisitorId(fingerprint, ip) {
  const dayTimestamp = Math.floor(Date.now() / (24 * 60 * 60 * 1000));
  return hashString(`${fingerprint}:${ip}:${dayTimestamp}`);
}

/**
 * 生成动态flag（每次提交都不同 - 基于时间戳）
 */
async function generateDynamicFlag(levelId, fingerprint, answer) {
  const timestamp = Date.now(); // 使用毫秒级时间戳，每次都不同
  const seed = `${levelId}_${fingerprint}_${answer}_${timestamp}`;
  const hash = await md5(seed);
  return hash;
}

// ==================== 访客统计系统 ====================

/**
 * 更新访客统计（使用 KV 存储）
 */
async function updateStats(env, visitorId) {
  if (!env.STATS_KV) {
    return { totalVisitors: 0, totalVisits: 0 };
  }

  try {
    // 获取当前统计
    const statsData = await env.STATS_KV.get('global_stats', { type: 'json' }) || {
      visitors: new Set(),
      visits: 0
    };

    // 访客集合（使用数组存储）
    const visitors = new Set(statsData.visitors || []);
    const oldVisitorCount = visitors.size;

    visitors.add(visitorId);
    const newVisit = visitors.size > oldVisitorCount;

    // 更新访问数
    const visits = (statsData.visits || 0) + 1;

    // 保存回 KV
    await env.STATS_KV.put('global_stats', JSON.stringify({
      visitors: Array.from(visitors),
      visits: visits,
      lastUpdate: Date.now()
    }));

    return {
      totalVisitors: visitors.size,
      totalVisits: visits,
      isNewVisitor: newVisit
    };
  } catch (error) {
    console.error('Stats update error:', error);
    return { totalVisitors: 0, totalVisits: 0 };
  }
}

/**
 * 获取统计数据
 */
async function getStats(env) {
  if (!env.STATS_KV) {
    return { totalVisitors: 0, totalVisits: 0 };
  }

  try {
    const statsData = await env.STATS_KV.get('global_stats', { type: 'json' });
    if (!statsData) {
      return { totalVisitors: 0, totalVisits: 0 };
    }

    return {
      totalVisitors: (statsData.visitors || []).length,
      totalVisits: statsData.visits || 0
    };
  } catch (error) {
    return { totalVisitors: 0, totalVisits: 0 };
  }
}

// ==================== 用户进度系统 ====================

/**
 * 获取用户进度（基于访客ID，24小时自动过期）
 */
async function getUserProgress(env, visitorId) {
  if (!env.STATS_KV) {
    return { completed: [], totalCompleted: 0 };
  }

  try {
    const progressKey = `progress:${visitorId}`;
    const progress = await env.STATS_KV.get(progressKey, { type: 'json' });

    if (!progress) {
      return { completed: [], totalCompleted: 0 };
    }

    return {
      completed: progress.completed || [],
      totalCompleted: (progress.completed || []).length
    };
  } catch (error) {
    console.error('Get progress error:', error);
    return { completed: [], totalCompleted: 0 };
  }
}

/**
 * 保存完成的关卡（24小时TTL）
 */
async function saveCompletedLevel(env, visitorId, levelId) {
  if (!env.STATS_KV) {
    return false;
  }

  try {
    const progressKey = `progress:${visitorId}`;
    const progress = await env.STATS_KV.get(progressKey, { type: 'json' }) || {
      completed: [],
      firstCompleteTime: null,
      lastCompleteTime: null
    };

    // 检查是否已完成
    if (!progress.completed.includes(levelId)) {
      progress.completed.push(levelId);
      progress.lastCompleteTime = Date.now();

      // 记录首次完成时间
      if (!progress.firstCompleteTime) {
        progress.firstCompleteTime = Date.now();
      }

      // 保存进度，24小时后自动过期
      await env.STATS_KV.put(progressKey, JSON.stringify(progress), {
        expirationTtl: 86400 // 24小时 = 86400秒
      });

      // 更新排行榜
      await updateLeaderboard(env, visitorId, progress);
    }

    return true;
  } catch (error) {
    console.error('Save progress error:', error);
    return false;
  }
}

// ==================== 排行榜系统 ====================

/**
 * 更新排行榜（基于完成题目数量和完成时间）
 */
async function updateLeaderboard(env, visitorId, progress) {
  if (!env.STATS_KV) {
    return;
  }

  try {
    const leaderboardKey = 'leaderboard:data';
    const leaderboard = await env.STATS_KV.get(leaderboardKey, { type: 'json' }) || {
      users: [],
      lastUpdate: Date.now()
    };

    // 查找用户是否已存在
    const userIndex = leaderboard.users.findIndex(u => u.id === visitorId);
    const completedCount = progress.completed.length;
    const totalTime = progress.lastCompleteTime - progress.firstCompleteTime;

    const userData = {
      id: visitorId,
      completed: completedCount,
      totalTime: totalTime,
      lastUpdate: Date.now()
    };

    if (userIndex >= 0) {
      leaderboard.users[userIndex] = userData;
    } else {
      leaderboard.users.push(userData);
    }

    // 排序：先按完成数量降序，再按总时间升序
    leaderboard.users.sort((a, b) => {
      if (b.completed !== a.completed) {
        return b.completed - a.completed;
      }
      return a.totalTime - b.totalTime;
    });

    // 只保留前100名
    leaderboard.users = leaderboard.users.slice(0, 100);
    leaderboard.lastUpdate = Date.now();

    // 保存排行榜（10分钟缓存）
    await env.STATS_KV.put(leaderboardKey, JSON.stringify(leaderboard), {
      expirationTtl: 600 // 10分钟 = 600秒
    });
  } catch (error) {
    console.error('Update leaderboard error:', error);
  }
}

/**
 * 获取排行榜数据
 */
async function getLeaderboard(env, currentVisitorId) {
  if (!env.STATS_KV) {
    return { ranks: [], currentUser: null };
  }

  try {
    const leaderboardKey = 'leaderboard:data';
    const leaderboard = await env.STATS_KV.get(leaderboardKey, { type: 'json' });

    if (!leaderboard || !leaderboard.users) {
      return { ranks: [], currentUser: null };
    }

    // 格式化排行榜数据
    const ranks = leaderboard.users.map((user, index) => ({
      rank: index + 1,
      id: user.id.substring(0, 8), // 只显示ID前8位
      completed: user.completed,
      time: formatTime(user.totalTime),
      isCurrentUser: user.id === currentVisitorId
    }));

    // 查找当前用户排名
    const currentUser = ranks.find(r => r.isCurrentUser);

    return {
      ranks: ranks.slice(0, 50), // 只返回前50名
      currentUser: currentUser,
      lastUpdate: leaderboard.lastUpdate
    };
  } catch (error) {
    console.error('Get leaderboard error:', error);
    return { ranks: [], currentUser: null };
  }
}

/**
 * 格式化时间（毫秒转为时分秒）
 */
function formatTime(ms) {
  if (!ms || ms < 0) return '0秒';

  const seconds = Math.floor(ms / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);

  if (hours > 0) {
    return `${hours}小时${minutes % 60}分`;
  } else if (minutes > 0) {
    return `${minutes}分${seconds % 60}秒`;
  } else {
    return `${seconds}秒`;
  }
}

// ==================== 关卡定义 ====================

const LEVELS = {
  // ========== Web 安全类 (1-15) ==========

  // Level 1: HTTP 头部检查
  1: {
    id: 1,
    name: 'HTTP Header Hunter',
    difficulty: '简单',
    category: 'Web安全',
    description: '找到隐藏在HTTP响应头中的线索，发送正确的请求头通过验证',
    hint: '服务器想要一个特殊的User-Agent...',
    testEnv: true,
    validate: async (request, fingerprint, answer) => {
      const userAgent = request.headers.get('user-agent') || '';
      if (userAgent.includes('SecurityBot/1.0')) {
        return {
          passed: true,
          flag: `flag{SecurityBot/1.0}`,
          message: '恭喜！你掌握了HTTP头部修改技巧'
        };
      }
      return {
        passed: false,
        message: '提示：服务器期待看到一个名为 SecurityBot/1.0 的User-Agent',
        hint: 'X-Hint: Try User-Agent: SecurityBot/1.0'
      };
    }
  },

  // Level 2: HTTP 方法检测
  2: {
    id: 2,
    name: 'Method Matters',
    difficulty: '简单',
    category: 'Web安全',
    description: '有些资源只对特定的HTTP方法开放',
    hint: 'GET不是唯一的方法...',
    testEnv: true,
    validate: async (request, fingerprint, answer) => {
      if (request.method === 'POST') {
        return {
          passed: true,
          flag: `flag{POST}`,
          message: 'POST方法成功！记住：不同的HTTP方法有不同的用途'
        };
      }
      return { passed: false, message: `当前方法: ${request.method}，试试其他方法？` };
    }
  },

  // Level 3: Referer 检查
  3: {
    id: 3,
    name: 'Referer Required',
    difficulty: '简单',
    category: 'Web安全',
    description: '某些页面需要从特定来源访问',
    hint: '服务器检查你从哪里来...',
    testEnv: true,
    validate: async (request, fingerprint, answer) => {
      const referer = request.headers.get('referer') || '';
      if (referer.includes('trusted-site.com')) {
        return {
          passed: true,
          flag: `flag{trusted-site.com}`,
          message: 'Referer伪造成功！但要注意：Referer可以被轻易伪造'
        };
      }
      return { passed: false, message: '提示：发送 Referer: https://trusted-site.com' };
    }
  },

  // Level 4: SQL注入识别
  4: {
    id: 4,
    name: 'SQL Injection Detective',
    difficulty: '中等',
    category: 'Web安全',
    description: '识别哪个输入是潜在的SQL注入攻击',
    hint: '找出危险的SQL模式',
    testEnv: 'sql-lab',
    validate: async (request, fingerprint, answer) => {
      const dangerous = "admin' OR '1'='1";
      if (answer === dangerous) {
        return {
          passed: true,
          flag: `flag{${answer}}`,
          message: '正确识别！永远不要相信用户输入，使用参数化查询'
        };
      }
      return { passed: false, message: '仔细观察，哪个输入会绕过认证？' };
    }
  },

  // Level 5: JWT 解析
  5: {
    id: 5,
    name: 'JWT Inspector',
    difficulty: '中等',
    category: 'Web安全',
    description: '解析JWT并找到用户名',
    hint: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoic3VwZXJ1c2VyIn0.signature',
    validate: async (request, fingerprint, answer) => {
      if (answer === 'admin') {
        return {
          passed: true,
          flag: `flag{${answer}}`,
          message: 'JWT解析成功！记住：JWT的payload可以被任何人解码'
        };
      }
      return { passed: false, message: 'JWT由三部分组成，用.分隔，payload是Base64编码的' };
    }
  },

  // Level 6: Cookie 操纵
  6: {
    id: 6,
    name: 'Cookie Monster',
    difficulty: '中等',
    category: 'Web安全',
    description: '修改Cookie中的权限字段',
    hint: '发送Cookie: role=admin',
    testEnv: true,
    validate: async (request, fingerprint, answer) => {
      const cookie = request.headers.get('cookie') || '';
      if (cookie.includes('role=admin')) {
        return {
          passed: true,
          flag: `flag{role=admin}`,
          message: 'Cookie伪造成功！永远在服务端验证权限'
        };
      }
      return { passed: false, message: '检查你的Cookie设置...' };
    }
  },

  // Level 7: SSRF 检测
  7: {
    id: 7,
    name: 'SSRF Spotter',
    difficulty: '困难',
    category: 'Web安全',
    description: '识别服务器端请求伪造(SSRF)漏洞',
    hint: '内网地址可能很危险...',
    validate: async (request, fingerprint, answer) => {
      const ssrfPayloads = ['http://localhost', 'http://127.0.0.1', 'http://169.254.169.254'];
      if (ssrfPayloads.some(payload => answer.includes(payload))) {
        return {
          passed: true,
          flag: `flag{${answer}}`,
          message: 'SSRF识别成功！始终验证和过滤URL参数'
        };
      }
      return { passed: false, message: '想想哪些URL可以访问内网资源' };
    }
  },

  // Level 8: XSS 识别
  8: {
    id: 8,
    name: 'XSS Hunter',
    difficulty: '中等',
    category: 'Web安全',
    description: '识别跨站脚本攻击(XSS)载荷',
    hint: '找出会执行JavaScript的输入',
    testEnv: 'xss-lab',
    validate: async (request, fingerprint, answer) => {
      if (answer.includes('<script>') || answer.includes('onerror=') || answer.includes('javascript:')) {
        return {
          passed: true,
          flag: `flag{${answer}}`,
          message: 'XSS识别成功！始终对用户输入进行HTML转义'
        };
      }
      return { passed: false, message: '提示：<script>alert(1)</script> 或事件处理器' };
    }
  },

  // Level 9: CORS 绕过
  9: {
    id: 9,
    name: 'CORS Bypass',
    difficulty: '困难',
    category: 'Web安全',
    description: '理解跨域资源共享机制',
    hint: 'Origin 头部决定了跨域访问',
    testEnv: true,
    validate: async (request, fingerprint, answer) => {
      const origin = request.headers.get('origin') || '';
      if (origin === 'https://trusted-domain.com') {
        return {
          passed: true,
          flag: `flag{https://trusted-domain.com}`,
          message: 'CORS理解正确！注意配置 Access-Control-Allow-Origin'
        };
      }
      return { passed: false, message: '发送正确的 Origin 头部' };
    }
  },

  // Level 10: 目录遍历
  10: {
    id: 10,
    name: 'Path Traversal',
    difficulty: '中等',
    category: 'Web安全',
    description: '识别目录遍历攻击载荷',
    hint: '向上跳转目录...',
    validate: async (request, fingerprint, answer) => {
      if (answer.includes('../') || answer.includes('..\\')) {
        return {
          passed: true,
          flag: `flag{${answer}}`,
          message: '目录遍历识别成功！始终验证文件路径'
        };
      }
      return { passed: false, message: '提示：../../etc/passwd' };
    }
  },

  // Level 11: 命令注入
  11: {
    id: 11,
    name: 'Command Injection',
    difficulty: '困难',
    category: 'Web安全',
    description: '识别命令注入攻击',
    hint: '如何在一行执行多个命令？',
    validate: async (request, fingerprint, answer) => {
      if (answer.includes(';') || answer.includes('&&') || answer.includes('||') || answer.includes('|')) {
        return {
          passed: true,
          flag: `flag{${answer}}`,
          message: '命令注入识别成功！永远不要直接执行用户输入'
        };
      }
      return { passed: false, message: '提示：使用 ; 或 && 连接命令' };
    }
  },

  // Level 12: XXE 攻击
  12: {
    id: 12,
    name: 'XXE Explorer',
    difficulty: '困难',
    category: 'Web安全',
    description: 'XML外部实体注入攻击',
    hint: 'ENTITY 可以引用外部资源',
    validate: async (request, fingerprint, answer) => {
      if (answer.includes('<!ENTITY') && answer.includes('SYSTEM')) {
        return {
          passed: true,
          flag: `flag{${answer}}`,
          message: 'XXE识别成功！禁用XML外部实体解析'
        };
      }
      return { passed: false, message: '提示：<!ENTITY xxe SYSTEM "file:///etc/passwd">' };
    }
  },

  // Level 13: CSRF Token
  13: {
    id: 13,
    name: 'CSRF Defender',
    difficulty: '中等',
    category: 'Web安全',
    description: '理解CSRF防护机制',
    hint: 'Token应该是随机且一次性的',
    validate: async (request, fingerprint, answer) => {
      if (answer.toLowerCase().includes('token') || answer.toLowerCase().includes('csrf')) {
        return {
          passed: true,
          flag: `flag{${answer}}`,
          message: 'CSRF理解正确！使用不可预测的token'
        };
      }
      return { passed: false, message: '如何防止跨站请求伪造？' };
    }
  },

  // Level 14: HTTP响应拆分
  14: {
    id: 14,
    name: 'Response Splitting',
    difficulty: '困难',
    category: 'Web安全',
    description: 'HTTP响应拆分攻击',
    hint: 'CRLF可以注入新的响应头',
    validate: async (request, fingerprint, answer) => {
      if (answer.includes('%0d%0a') || answer.includes('\\r\\n') || answer.includes('\r\n')) {
        return {
          passed: true,
          flag: `flag{${answer}}`,
          message: '响应拆分识别成功！过滤CRLF字符'
        };
      }
      return { passed: false, message: '提示：%0d%0a 或 \\r\\n' };
    }
  },

  // Level 15: 文件上传绕过
  15: {
    id: 15,
    name: 'Upload Bypass',
    difficulty: '困难',
    category: 'Web安全',
    description: '绕过文件上传限制',
    hint: '文件扩展名不是唯一的判断标准',
    validate: async (request, fingerprint, answer) => {
      const bypasses = ['.php.jpg', '.php5', '.phtml', 'shell.php%00.jpg', 'Content-Type'];
      if (bypasses.some(b => answer.includes(b))) {
        return {
          passed: true,
          flag: `flag{${answer}}`,
          message: '上传绕过识别成功！验证文件内容和MIME类型'
        };
      }
      return { passed: false, message: '提示：双重扩展名、空字节、MIME伪造' };
    }
  },

  // ========== 密码学类 (16-25) ==========

  // Level 16: Base64 解码
  16: {
    id: 16,
    name: 'Base64 Decoder',
    difficulty: '简单',
    category: '密码学',
    description: '解码Base64字符串找到密码',
    hint: 'U2VjcmV0UGFzc3dvcmQxMjM=',
    validate: async (request, fingerprint, answer) => {
      if (answer === 'SecretPassword123') {
        return {
          passed: true,
          flag: `flag{${answer}}`,
          message: '正确！Base64是最基础的编码方式'
        };
      }
      return { passed: false, message: '密码错误，再仔细看看提示' };
    }
  },

  // Level 17: XOR 密码学
  17: {
    id: 17,
    name: 'XOR Cipher',
    difficulty: '中等',
    category: '密码学',
    description: '使用XOR解密消息（密钥：KEY）',
    hint: '密文(hex): 02170b1c01',
    validate: async (request, fingerprint, answer) => {
      if (answer.toUpperCase() === 'HELLO') {
        return {
          passed: true,
          flag: `flag{${answer}}`,
          message: 'XOR解密成功！XOR是对称加密的基础'
        };
      }
      return { passed: false, message: '提示：XOR每个字节与密钥字节' };
    }
  },

  // Level 18: 凯撒密码
  18: {
    id: 18,
    name: 'Caesar Shift',
    difficulty: '简单',
    category: '密码学',
    description: '破解凯撒密码（位移13）',
    hint: '密文: FRPHEL',
    validate: async (request, fingerprint, answer) => {
      if (answer.toUpperCase() === 'COMEDY') {
        return {
          passed: true,
          flag: `flag{${answer}}`,
          message: 'ROT13解密成功！古老但经典的密码学'
        };
      }
      return { passed: false, message: '提示：ROT13，每个字母向后移动13位' };
    }
  },

  // Level 19: MD5碰撞
  19: {
    id: 19,
    name: 'Hash Collision',
    difficulty: '中等',
    category: '密码学',
    description: 'MD5已经不安全了，为什么？',
    hint: '两个不同的输入可以产生相同的...',
    validate: async (request, fingerprint, answer) => {
      if (answer.toLowerCase().includes('碰撞') || answer.toLowerCase().includes('collision')) {
        return {
          passed: true,
          flag: `flag{${answer}}`,
          message: '正确！MD5存在碰撞攻击，应使用SHA-256'
        };
      }
      return { passed: false, message: '提示：哈希碰撞' };
    }
  },

  // Level 20: AES理论
  20: {
    id: 20,
    name: 'AES Master',
    difficulty: '中等',
    category: '密码学',
    description: 'AES-128的密钥长度是多少位？',
    hint: '这是对称加密的黄金标准',
    validate: async (request, fingerprint, answer) => {
      if (answer === '128' || answer === '128位' || answer === '128 bits') {
        return {
          passed: true,
          flag: `flag{${answer}}`,
          message: '正确！AES支持128、192、256位密钥'
        };
      }
      return { passed: false, message: 'AES-128中的128代表什么？' };
    }
  },

  // Level 21: RSA公私钥
  21: {
    id: 21,
    name: 'RSA Keys',
    difficulty: '中等',
    category: '密码学',
    description: 'RSA中，哪个密钥用于加密公开数据？',
    hint: '公开的密钥...',
    validate: async (request, fingerprint, answer) => {
      if (answer.includes('公钥') || answer.toLowerCase().includes('public')) {
        return {
          passed: true,
          flag: `flag{${answer}}`,
          message: 'RSA理解正确！公钥加密，私钥解密'
        };
      }
      return { passed: false, message: '提示：公钥和私钥，谁用于加密？' };
    }
  },

  // Level 22: Hex转ASCII
  22: {
    id: 22,
    name: 'Hex Decoder',
    difficulty: '简单',
    category: '密码学',
    description: '将十六进制转换为ASCII',
    hint: '48656c6c6f',
    validate: async (request, fingerprint, answer) => {
      if (answer === 'Hello') {
        return {
          passed: true,
          flag: `flag{${answer}}`,
          message: 'Hex解码成功！每两个字符代表一个字节'
        };
      }
      return { passed: false, message: '提示：48=H, 65=e...' };
    }
  },

  // Level 23: 哈希彩虹表
  23: {
    id: 23,
    name: 'Rainbow Table',
    difficulty: '困难',
    category: '密码学',
    description: '如何防御彩虹表攻击？',
    hint: '加点"盐"...',
    validate: async (request, fingerprint, answer) => {
      if (answer.toLowerCase().includes('salt') || answer.includes('盐')) {
        return {
          passed: true,
          flag: `flag{${answer}}`,
          message: '正确！加盐可以防止彩虹表攻击'
        };
      }
      return { passed: false, message: '提示：在密码哈希前添加随机数据' };
    }
  },

  // Level 24: 对称vs非对称
  24: {
    id: 24,
    name: 'Crypto Types',
    difficulty: '简单',
    category: '密码学',
    description: 'AES是对称加密还是非对称加密？',
    hint: '使用相同的密钥...',
    validate: async (request, fingerprint, answer) => {
      if (answer.includes('对称') || answer.toLowerCase().includes('symmetric')) {
        return {
          passed: true,
          flag: `flag{${answer}}`,
          message: '正确！对称加密使用相同密钥加密解密'
        };
      }
      return { passed: false, message: '提示：加密和解密使用同一个密钥' };
    }
  },

  // Level 25: 密钥交换
  25: {
    id: 25,
    name: 'Key Exchange',
    difficulty: '困难',
    category: '密码学',
    description: 'Diffie-Hellman算法用于什么？',
    hint: '在不安全信道上...',
    validate: async (request, fingerprint, answer) => {
      if (answer.includes('密钥交换') || answer.toLowerCase().includes('key exchange')) {
        return {
          passed: true,
          flag: `flag{${answer}}`,
          message: 'DH密钥交换理解正确！允许安全协商密钥'
        };
      }
      return { passed: false, message: '提示：两方如何在不安全信道建立共享密钥' };
    }
  },

  // ========== 协议分析类 (26-30) ==========

  // Level 26: HTTP状态码
  26: {
    id: 26,
    name: 'Status Code 418',
    difficulty: '简单',
    category: '协议分析',
    description: 'HTTP 418状态码的含义是什么？',
    hint: '一个愚人节玩笑...',
    validate: async (request, fingerprint, answer) => {
      if (answer.includes('茶壶') || answer.toLowerCase().includes('teapot')) {
        return {
          passed: true,
          flag: `flag{${answer}}`,
          message: '正确！418 I\'m a teapot - RFC 2324'
        };
      }
      return { passed: false, message: '提示：I\'m a ...' };
    }
  },

  // Level 27: DNS记录类型
  27: {
    id: 27,
    name: 'DNS Records',
    difficulty: '中等',
    category: '协议分析',
    description: '哪种DNS记录用于邮件服务器？',
    hint: 'Mail eXchange...',
    validate: async (request, fingerprint, answer) => {
      if (answer.toUpperCase() === 'MX') {
        return {
          passed: true,
          flag: `flag{${answer}}`,
          message: 'DNS理解正确！MX记录指向邮件服务器'
        };
      }
      return { passed: false, message: '提示：A、AAAA、CNAME、MX、TXT...' };
    }
  },

  // Level 28: TCP三次握手
  28: {
    id: 28,
    name: 'TCP Handshake',
    difficulty: '中等',
    category: '协议分析',
    description: 'TCP三次握手的顺序是？',
    hint: 'SYN, SYN-ACK, ???',
    validate: async (request, fingerprint, answer) => {
      if (answer.toUpperCase().includes('ACK') || answer.includes('确认')) {
        return {
          passed: true,
          flag: `flag{${answer}}`,
          message: '正确！SYN -> SYN-ACK -> ACK'
        };
      }
      return { passed: false, message: '提示：SYN、SYN-ACK、???' };
    }
  },

  // Level 29: TLS版本
  29: {
    id: 29,
    name: 'TLS Version',
    difficulty: '中等',
    category: '协议分析',
    description: '目前推荐使用的TLS最低版本是？',
    hint: 'TLS 1.0和1.1已被废弃...',
    validate: async (request, fingerprint, answer) => {
      if (answer.includes('1.2') || answer.includes('1.3')) {
        return {
          passed: true,
          flag: `flag{${answer}}`,
          message: '正确！TLS 1.2+是当前标准'
        };
      }
      return { passed: false, message: '提示：1.2或更高' };
    }
  },

  // Level 30: WebSocket协议
  30: {
    id: 30,
    name: 'WebSocket Upgrade',
    difficulty: '困难',
    category: '协议分析',
    description: 'WebSocket握手使用哪个HTTP头部？',
    hint: 'HTTP升级到WebSocket...',
    validate: async (request, fingerprint, answer) => {
      if (answer.toLowerCase().includes('upgrade') || answer.includes('升级')) {
        return {
          passed: true,
          flag: `flag{${answer}}`,
          message: 'WebSocket理解正确！Upgrade: websocket'
        };
      }
      return { passed: false, message: '提示：Upgrade 头部' };
    }
  },

  // ========== 进阶挑战 (31-35) ==========

  // Level 31: 正则表达式绕过
  31: {
    id: 31,
    name: 'Regex Bypass',
    difficulty: '困难',
    category: 'Web安全',
    description: '如何绕过黑名单正则 /admin/',
    hint: '大小写、编码、路径...',
    validate: async (request, fingerprint, answer) => {
      const bypasses = ['Admin', 'ADMIN', '%61dmin', 'admin/', './admin'];
      if (bypasses.some(b => answer.includes(b))) {
        return {
          passed: true,
          flag: `flag{${answer}}`,
          message: '绕过成功！使用白名单而不是黑名单'
        };
      }
      return { passed: false, message: '提示：大小写、URL编码、路径规范化' };
    }
  },

  // Level 32: JWT None算法
  32: {
    id: 32,
    name: 'JWT Algorithm None',
    difficulty: '困难',
    category: 'Web安全',
    description: 'JWT的"none"算法漏洞',
    hint: '不验证签名...',
    validate: async (request, fingerprint, answer) => {
      if (answer.toLowerCase().includes('none') || answer.includes('不验证')) {
        return {
          passed: true,
          flag: `flag{${answer}}`,
          message: 'JWT漏洞理解正确！禁用none算法'
        };
      }
      return { passed: false, message: '提示：alg: "none"' };
    }
  },

  // Level 33: 时序攻击
  33: {
    id: 33,
    name: 'Timing Attack',
    difficulty: '困难',
    category: '密码学',
    description: '如何防御时序攻击？',
    hint: '比较时间应该是...',
    validate: async (request, fingerprint, answer) => {
      if (answer.includes('恒定') || answer.toLowerCase().includes('constant')) {
        return {
          passed: true,
          flag: `flag{${answer}}`,
          message: '正确！使用恒定时间比较函数'
        };
      }
      return { passed: false, message: '提示：constant-time comparison' };
    }
  },

  // Level 34: HSTS头部
  34: {
    id: 34,
    name: 'HSTS Header',
    difficulty: '中等',
    category: 'Web安全',
    description: 'HSTS头部的作用是什么？',
    hint: 'Strict-Transport-Security...',
    validate: async (request, fingerprint, answer) => {
      if (answer.toLowerCase().includes('https') || answer.includes('强制')) {
        return {
          passed: true,
          flag: `flag{${answer}}`,
          message: 'HSTS理解正确！强制使用HTTPS'
        };
      }
      return { passed: false, message: '提示：强制浏览器使用安全连接' };
    }
  },

  // Level 35: 最终挑战
  35: {
    id: 35,
    name: 'Final Challenge',
    difficulty: '专家',
    category: '综合',
    description: '说出你最喜欢的安全工具或技术',
    hint: '你已经掌握了很多安全知识！',
    validate: async (request, fingerprint, answer) => {
      if (answer && answer.length > 3) {
        return {
          passed: true,
          flag: `flag{${answer}}`,
          message: `恭喜通关！ "${answer}" 是个好选择！你已经完成了所有35个挑战！`
        };
      }
      return { passed: false, message: '分享你的安全工具或技术经验' };
    }
  }
};

// ==================== API 处理器 ====================

/**
 * 处理获取访客信息请求
 */
async function handleVisitorInfo(request, env) {
  const ip = request.headers.get('cf-connecting-ip') || 'unknown';
  const fingerprint = generateFingerprint(request);
  const visitorId = generateVisitorId(fingerprint, ip);

  // 更新统计
  const stats = await updateStats(env, visitorId);

  return new Response(JSON.stringify({
    ip,
    fingerprint,
    visitorId,
    expiresIn: '24小时',
    totalVisitors: stats.totalVisitors,
    totalVisits: stats.totalVisits
  }), {
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*'
    }
  });
}

/**
 * 处理获取统计信息请求
 */
async function handleStats(request, env) {
  const stats = await getStats(env);
  return new Response(JSON.stringify(stats), {
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*'
    }
  });
}

/**
 * 处理获取关卡列表请求
 */
async function handleLevelsList(request) {
  const levels = Object.values(LEVELS).map(level => ({
    id: level.id,
    name: level.name,
    difficulty: level.difficulty,
    category: level.category,
    description: level.description,
    testEnv: level.testEnv || null
  }));

  return new Response(JSON.stringify(levels), {
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*'
    }
  });
}

/**
 * 处理关卡详情请求
 */
async function handleLevelDetail(request, levelId) {
  const level = LEVELS[levelId];
  if (!level) {
    return new Response(JSON.stringify({ error: '关卡不存在' }), {
      status: 404,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      }
    });
  }

  const response = {
    id: level.id,
    name: level.name,
    difficulty: level.difficulty,
    category: level.category,
    description: level.description,
    hint: level.hint,
    testEnv: level.testEnv || null
  };

  const headers = {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*'
  };

  if (levelId === '1') {
    headers['X-Hint'] = 'I only talk to SecurityBot/1.0';
  }

  return new Response(JSON.stringify(response), { headers });
}

/**
 * 处理答案提交请求
 */
async function handleSubmitAnswer(request, env) {
  try {
    const { levelId, answer } = await request.json();
    const level = LEVELS[levelId];

    if (!level) {
      return new Response(JSON.stringify({ error: '关卡不存在' }), {
        status: 404,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        }
      });
    }

    const fingerprint = generateFingerprint(request);
    const ip = request.headers.get('cf-connecting-ip') || 'unknown';
    const visitorId = generateVisitorId(fingerprint, ip);
    const result = await level.validate(request, fingerprint, answer);

    // 如果答案正确，保存进度
    if (result.passed && env.STATS_KV) {
      await saveCompletedLevel(env, visitorId, levelId);
    }

    return new Response(JSON.stringify(result), {
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      }
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: '无效的请求' }), {
      status: 400,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      }
    });
  }
}

/**
 * 处理获取进度请求
 */
async function handleGetProgress(request, env) {
  try {
    const fingerprint = generateFingerprint(request);
    const ip = request.headers.get('cf-connecting-ip') || 'unknown';
    const visitorId = generateVisitorId(fingerprint, ip);

    const progress = await getUserProgress(env, visitorId);

    return new Response(JSON.stringify({
      visitorId: visitorId.substring(0, 8),
      completed: progress.completed,
      totalCompleted: progress.totalCompleted,
      total: 35
    }), {
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      }
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: '获取进度失败' }), {
      status: 500,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      }
    });
  }
}

/**
 * 处理获取排行榜请求
 */
async function handleGetLeaderboard(request, env) {
  try {
    const fingerprint = generateFingerprint(request);
    const ip = request.headers.get('cf-connecting-ip') || 'unknown';
    const visitorId = generateVisitorId(fingerprint, ip);

    const leaderboard = await getLeaderboard(env, visitorId);

    return new Response(JSON.stringify(leaderboard), {
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      }
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: '获取排行榜失败' }), {
      status: 500,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      }
    });
  }
}

/**
 * 处理测试环境请求（用于Web安全挑战）
 */
async function handleTestEnv(request, levelId) {
  const testEnvs = {
    // Level 1: HTTP Header 测试环境
    '1': () => {
      const ua = request.headers.get('user-agent') || '';
      return new Response(JSON.stringify({
        message: '欢迎来到 Level 1 测试环境',
        yourUserAgent: ua,
        expectedUserAgent: 'SecurityBot/1.0',
        hint: '修改你的 User-Agent 头部'
      }), {
        headers: {
          'Content-Type': 'application/json',
          'X-Level-Hint': 'I only talk to SecurityBot/1.0',
          'Access-Control-Allow-Origin': '*'
        }
      });
    },

    // Level 2: POST 方法测试环境
    '2': () => {
      return new Response(JSON.stringify({
        message: '欢迎来到 Level 2 测试环境',
        currentMethod: request.method,
        hint: '试试用 POST 方法访问这个 URL',
        methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']
      }), {
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, PATCH, OPTIONS'
        }
      });
    },

    // Level 3: Referer 测试环境
    '3': () => {
      const referer = request.headers.get('referer') || 'none';
      return new Response(JSON.stringify({
        message: '欢迎来到 Level 3 测试环境',
        yourReferer: referer,
        expectedReferer: 'https://trusted-site.com',
        hint: '发送正确的 Referer 头部'
      }), {
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        }
      });
    },

    // Level 6: Cookie 测试环境
    '6': () => {
      const cookie = request.headers.get('cookie') || 'none';
      return new Response(JSON.stringify({
        message: '欢迎来到 Level 6 测试环境',
        yourCookie: cookie,
        hint: '发送包含 role=admin 的 Cookie',
        example: 'Cookie: role=admin'
      }), {
        headers: {
          'Content-Type': 'application/json',
          'Set-Cookie': 'role=guest; Path=/',
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Credentials': 'true'
        }
      });
    },

    // Level 9: CORS 测试环境
    '9': () => {
      const origin = request.headers.get('origin') || 'none';
      return new Response(JSON.stringify({
        message: '欢迎来到 Level 9 测试环境',
        yourOrigin: origin,
        expectedOrigin: 'https://trusted-domain.com',
        hint: '发送正确的 Origin 头部'
      }), {
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': origin === 'https://trusted-domain.com' ? origin : '*'
        }
      });
    },

    // 通用SQL注入测试环境
    'sql-lab': () => {
      return new Response(SQL_LAB_HTML, {
        headers: { 'Content-Type': 'text/html;charset=UTF-8' }
      });
    },

    // XSS测试环境
    'xss-lab': () => {
      return new Response(XSS_LAB_HTML, {
        headers: { 'Content-Type': 'text/html;charset=UTF-8' }
      });
    }
  };

  const handler = testEnvs[levelId];
  if (handler) {
    return handler();
  }

  return new Response(JSON.stringify({ error: '此关卡没有测试环境' }), {
    status: 404,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*'
    }
  });
}

/**
 * 主请求处理器
 */
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // CORS 预检请求
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, User-Agent, Cookie, Origin, Referer'
        }
      });
    }

    // API 路由
    if (path === '/api/visitor') {
      return handleVisitorInfo(request, env);
    }

    if (path === '/api/stats') {
      return handleStats(request, env);
    }

    if (path === '/api/levels') {
      return handleLevelsList(request);
    }

    if (path.startsWith('/api/level/')) {
      const levelId = path.split('/').pop();
      return handleLevelDetail(request, levelId);
    }

    if (path === '/api/submit') {
      return handleSubmitAnswer(request, env);
    }

    if (path === '/api/progress') {
      return handleGetProgress(request, env);
    }

    if (path === '/api/leaderboard') {
      return handleGetLeaderboard(request, env);
    }

    // 测试环境路由
    if (path.startsWith('/test/')) {
      const levelId = path.split('/').pop();
      return handleTestEnv(request, levelId);
    }

    // 返回前端页面
    if (path === '/' || path === '/index.html') {
      return new Response(HTML_CONTENT, {
        headers: { 'Content-Type': 'text/html;charset=UTF-8' }
      });
    }

    return new Response('Not Found', { status: 404 });
  }
};

// ==================== 前端HTML ====================

const HTML_CONTENT = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>网络安全闯关游戏 | CTF Challenge</title>
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }

    body {
      font-family: 'Consolas', 'Monaco', monospace;
      background: linear-gradient(135deg, #0a0e27 0%, #1a1a2e 100%);
      color: #00ff41;
      min-height: 100vh;
      padding: 20px;
    }

    .container {
      max-width: 1200px;
      margin: 0 auto;
    }

    header {
      text-align: center;
      margin-bottom: 40px;
      padding: 30px;
      background: rgba(0, 255, 65, 0.1);
      border: 2px solid #00ff41;
      border-radius: 10px;
      box-shadow: 0 0 20px rgba(0, 255, 65, 0.3);
      position: relative;
      overflow: hidden;
    }

    h1 {
      font-size: 2.5em;
      text-shadow: 0 0 10px #00ff41;
      margin-bottom: 10px;
    }

    .subtitle {
      color: #00d4ff;
      font-size: 1.1em;
      margin-bottom: 20px;
    }

    /* 进度统计 */
    .progress-bar-container {
      background: rgba(10, 14, 39, 0.6);
      border: 2px solid #00ff41;
      border-radius: 10px;
      padding: 20px;
      margin-top: 20px;
    }

    .progress-info {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 10px;
      color: #00d4ff;
    }

    .progress-text {
      font-size: 1.1em;
      font-weight: bold;
    }

    .progress-bar {
      width: 100%;
      height: 25px;
      background: rgba(10, 14, 39, 0.8);
      border-radius: 15px;
      overflow: hidden;
      border: 1px solid #00ff41;
      position: relative;
    }

    .progress-fill {
      height: 100%;
      background: linear-gradient(90deg, #00ff41, #ffa500);
      transition: width 0.5s ease;
      box-shadow: 0 0 10px rgba(255, 165, 0, 0.6);
      position: relative;
    }

    .progress-fill::after {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.3), transparent);
      animation: shimmer 2s infinite;
    }

    @keyframes shimmer {
      0% { transform: translateX(-100%); }
      100% { transform: translateX(100%); }
    }

    /* 排行榜按钮 */
    .leaderboard-btn {
      margin-top: 15px;
      padding: 12px 30px;
      background: linear-gradient(135deg, #00ff41 0%, #00d4ff 100%);
      color: #0a0e27;
      border: none;
      border-radius: 5px;
      font-size: 16px;
      font-weight: bold;
      cursor: pointer;
      transition: all 0.3s ease;
      box-shadow: 0 4px 15px rgba(0, 255, 65, 0.3);
      width: 100%;
      font-family: 'Consolas', 'Monaco', monospace;
    }

    .leaderboard-btn:hover {
      transform: translateY(-2px);
      box-shadow: 0 6px 20px rgba(0, 255, 65, 0.5);
    }

    /* 排行榜模态框 */
    .leaderboard-modal {
      max-width: 800px;
      max-height: 90vh;
      overflow-y: auto;
    }

    .leaderboard-info {
      text-align: center;
      color: #00d4ff;
      margin-bottom: 20px;
      padding: 10px;
      background: rgba(0, 212, 255, 0.1);
      border-radius: 5px;
    }

    .leaderboard-info p {
      margin: 5px 0;
      font-size: 14px;
    }

    .current-rank {
      background: rgba(255, 165, 0, 0.2);
      border: 2px solid #ffa500;
      border-radius: 8px;
      padding: 15px;
      margin-bottom: 20px;
      text-align: center;
      color: #ffa500;
      font-size: 16px;
      font-weight: bold;
    }

    .leaderboard-table-container {
      overflow-x: auto;
      max-height: 500px;
      overflow-y: auto;
    }

    .leaderboard-table {
      width: 100%;
      border-collapse: collapse;
      color: #00ff41;
    }

    .leaderboard-table thead {
      position: sticky;
      top: 0;
      background: rgba(10, 14, 39, 0.95);
      z-index: 10;
    }

    .leaderboard-table th {
      padding: 12px;
      text-align: left;
      border-bottom: 2px solid #00ff41;
      font-size: 14px;
      color: #00d4ff;
    }

    .leaderboard-table td {
      padding: 10px 12px;
      border-bottom: 1px solid rgba(0, 255, 65, 0.2);
      font-size: 14px;
    }

    .leaderboard-table tr:hover {
      background: rgba(0, 255, 65, 0.1);
    }

    .leaderboard-table tr.current-user {
      background: rgba(255, 165, 0, 0.2);
      border-left: 4px solid #ffa500;
    }

    .leaderboard-table tr.current-user td {
      color: #ffa500;
      font-weight: bold;
    }

    .leaderboard-table .rank-1 {
      color: #ffd700;
      font-weight: bold;
      font-size: 16px;
    }

    .leaderboard-table .rank-2 {
      color: #c0c0c0;
      font-weight: bold;
    }

    .leaderboard-table .rank-3 {
      color: #cd7f32;
      font-weight: bold;
    }

    .leaderboard-table .loading {
      text-align: center;
      padding: 40px;
      color: #00d4ff;
    }

    /* 打字机效果 */
    .typewriter-container {
      background: rgba(10, 14, 39, 0.6);
      border-left: 4px solid #00ff41;
      padding: 15px 20px;
      margin-top: 20px;
      text-align: left;
      border-radius: 5px;
      min-height: 60px;
    }

    .typewriter-text {
      color: #00d4ff;
      font-size: 1em;
      line-height: 1.6;
      display: inline;
    }

    .typewriter-cursor {
      display: inline-block;
      width: 10px;
      height: 18px;
      background: #00ff41;
      margin-left: 2px;
      animation: blink 1s infinite;
      vertical-align: text-bottom;
    }

    @keyframes blink {
      0%, 50% { opacity: 1; }
      51%, 100% { opacity: 0; }
    }

    .levels-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
      gap: 20px;
      margin-bottom: 40px;
    }

    .level-card {
      background: rgba(26, 26, 46, 0.8);
      border: 2px solid #00ff41;
      border-radius: 10px;
      padding: 20px;
      cursor: pointer;
      transition: all 0.3s ease;
      position: relative;
      overflow: hidden;
    }

    /* 已完成关卡样式 */
    .level-card.completed {
      background: rgba(0, 255, 65, 0.15);
      border-color: #ffa500;
      box-shadow: 0 0 15px rgba(255, 165, 0, 0.4);
    }

    .level-card.completed::after {
      content: '✓';
      position: absolute;
      top: 10px;
      right: 10px;
      width: 40px;
      height: 40px;
      background: #ffa500;
      color: #0a0e27;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 24px;
      font-weight: bold;
      box-shadow: 0 0 10px rgba(255, 165, 0, 0.6);
      animation: checkmark 0.5s ease;
    }

    @keyframes checkmark {
      0% {
        transform: scale(0) rotate(0deg);
        opacity: 0;
      }
      50% {
        transform: scale(1.2) rotate(180deg);
      }
      100% {
        transform: scale(1) rotate(360deg);
        opacity: 1;
      }
    }

    .level-card:hover {
      transform: translateY(-5px);
      box-shadow: 0 5px 25px rgba(0, 255, 65, 0.5);
      border-color: #00d4ff;
    }

    .level-card.completed:hover {
      box-shadow: 0 5px 25px rgba(255, 165, 0, 0.6);
    }

    .level-card::before {
      content: '';
      position: absolute;
      top: 0;
      left: -100%;
      width: 100%;
      height: 100%;
      background: linear-gradient(90deg, transparent, rgba(0, 255, 65, 0.2), transparent);
      transition: left 0.5s;
    }

    .level-card:hover::before {
      left: 100%;
    }

    .level-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 10px;
    }

    .level-id {
      background: #00ff41;
      color: #0a0e27;
      padding: 5px 10px;
      border-radius: 5px;
      font-weight: bold;
    }

    .difficulty {
      padding: 5px 10px;
      border-radius: 5px;
      font-size: 0.9em;
    }

    .difficulty.简单 { background: #00ff41; color: #0a0e27; }
    .difficulty.中等 { background: #ffa500; color: #0a0e27; }
    .difficulty.困难 { background: #ff4444; color: white; }
    .difficulty.专家 { background: #ff00ff; color: white; }

    .level-name {
      font-size: 1.3em;
      margin: 10px 0;
      color: #00d4ff;
    }

    .category {
      color: #00ff41;
      font-size: 0.9em;
      margin-bottom: 10px;
    }

    .description {
      color: #a0a0a0;
      line-height: 1.5;
    }

    .test-env-btn {
      margin-top: 10px;
      padding: 8px 15px;
      background: rgba(0, 212, 255, 0.2);
      color: #00d4ff;
      border: 1px solid #00d4ff;
      border-radius: 5px;
      font-size: 0.85em;
      cursor: pointer;
      transition: all 0.3s;
      font-family: 'Consolas', monospace;
      width: 100%;
    }

    .test-env-btn:hover {
      background: rgba(0, 212, 255, 0.4);
      box-shadow: 0 0 10px rgba(0, 212, 255, 0.5);
    }

    .test-env-btn-modal {
      width: 100%;
      padding: 12px;
      background: rgba(0, 212, 255, 0.2);
      color: #00d4ff;
      border: 2px solid #00d4ff;
      border-radius: 5px;
      font-size: 1em;
      font-weight: bold;
      cursor: pointer;
      transition: all 0.3s;
      font-family: 'Consolas', monospace;
    }

    .test-env-btn-modal:hover {
      background: rgba(0, 212, 255, 0.4);
      box-shadow: 0 0 15px rgba(0, 212, 255, 0.6);
      transform: scale(1.02);
    }

    .modal {
      display: none;
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0, 0, 0, 0.8);
      z-index: 1000;
      align-items: center;
      justify-content: center;
    }

    .modal.active {
      display: flex;
    }

    .modal-content {
      background: #1a1a2e;
      border: 2px solid #00ff41;
      border-radius: 10px;
      padding: 30px;
      max-width: 600px;
      width: 90%;
      max-height: 80vh;
      overflow-y: auto;
      box-shadow: 0 0 50px rgba(0, 255, 65, 0.5);
    }

    .close-btn {
      float: right;
      font-size: 28px;
      color: #ff4444;
      cursor: pointer;
      line-height: 1;
    }

    .close-btn:hover {
      color: #ff6666;
    }

    .hint-box {
      background: rgba(0, 212, 255, 0.1);
      border-left: 4px solid #00d4ff;
      padding: 15px;
      margin: 20px 0;
      border-radius: 5px;
    }

    .input-group {
      margin: 20px 0;
    }

    .input-group label {
      display: block;
      margin-bottom: 10px;
      color: #00ff41;
    }

    .input-group input {
      width: 100%;
      padding: 12px;
      background: #0a0e27;
      border: 2px solid #00ff41;
      border-radius: 5px;
      color: #00ff41;
      font-family: 'Consolas', monospace;
      font-size: 1em;
    }

    .input-group input:focus {
      outline: none;
      border-color: #00d4ff;
      box-shadow: 0 0 10px rgba(0, 212, 255, 0.5);
    }

    .submit-btn {
      width: 100%;
      padding: 15px;
      background: #00ff41;
      color: #0a0e27;
      border: none;
      border-radius: 5px;
      font-size: 1.1em;
      font-weight: bold;
      cursor: pointer;
      transition: all 0.3s;
      font-family: 'Consolas', monospace;
    }

    .submit-btn:hover {
      background: #00d4ff;
      transform: scale(1.05);
    }

    .result-box {
      margin-top: 20px;
      padding: 15px;
      border-radius: 5px;
      display: none;
      animation: fadeIn 0.3s ease;
    }

    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(-10px); }
      to { opacity: 1; transform: translateY(0); }
    }

    /* 成功提交光效 */
    .result-box.success {
      background: rgba(0, 255, 65, 0.2);
      border: 2px solid #00ff41;
      display: block;
      animation: successGlow 1s ease-in-out;
      box-shadow: 0 0 20px rgba(0, 255, 65, 0.6),
                  0 0 40px rgba(0, 255, 65, 0.4),
                  inset 0 0 10px rgba(0, 255, 65, 0.2);
    }

    @keyframes successGlow {
      0% {
        box-shadow: 0 0 5px rgba(0, 255, 65, 0.3);
        transform: scale(0.95);
      }
      50% {
        box-shadow: 0 0 30px rgba(0, 255, 65, 0.8),
                    0 0 60px rgba(0, 255, 65, 0.5),
                    inset 0 0 15px rgba(0, 255, 65, 0.3);
        transform: scale(1.02);
      }
      100% {
        box-shadow: 0 0 20px rgba(0, 255, 65, 0.6),
                    0 0 40px rgba(0, 255, 65, 0.4),
                    inset 0 0 10px rgba(0, 255, 65, 0.2);
        transform: scale(1);
      }
    }

    /* 失败提交光效 */
    .result-box.error {
      background: rgba(255, 68, 68, 0.2);
      border: 2px solid #ff4444;
      color: #ff4444;
      display: block;
      animation: errorShake 0.5s ease-in-out;
      box-shadow: 0 0 20px rgba(255, 68, 68, 0.6),
                  0 0 40px rgba(255, 68, 68, 0.3),
                  inset 0 0 10px rgba(255, 68, 68, 0.2);
    }

    @keyframes errorShake {
      0%, 100% {
        transform: translateX(0);
        box-shadow: 0 0 10px rgba(255, 68, 68, 0.4);
      }
      10%, 30%, 50%, 70%, 90% {
        transform: translateX(-5px);
        box-shadow: 0 0 25px rgba(255, 68, 68, 0.7),
                    0 0 50px rgba(255, 68, 68, 0.4),
                    inset 0 0 15px rgba(255, 68, 68, 0.3);
      }
      20%, 40%, 60%, 80% {
        transform: translateX(5px);
        box-shadow: 0 0 25px rgba(255, 68, 68, 0.7),
                    0 0 50px rgba(255, 68, 68, 0.4),
                    inset 0 0 15px rgba(255, 68, 68, 0.3);
      }
    }

    .flag {
      background: #0a0e27;
      padding: 10px;
      border-radius: 5px;
      margin-top: 10px;
      font-family: 'Courier New', monospace;
      word-break: break-all;
      color: #ffa500;
      font-weight: bold;
      animation: flagReveal 0.6s ease;
      box-shadow: 0 0 15px rgba(255, 165, 0, 0.5);
    }

    @keyframes flagReveal {
      0% {
        opacity: 0;
        transform: scale(0.8);
        filter: blur(5px);
      }
      50% {
        transform: scale(1.05);
      }
      100% {
        opacity: 1;
        transform: scale(1);
        filter: blur(0);
      }
    }

    /* 悬浮窗样式 */
    .floating-info {
      position: fixed;
      bottom: 20px;
      right: 20px;
      background: rgba(26, 26, 46, 0.95);
      border: 2px solid #00ff41;
      border-radius: 10px;
      padding: 15px 20px;
      box-shadow: 0 5px 30px rgba(0, 255, 65, 0.4);
      z-index: 999;
      transition: opacity 0.5s ease, transform 0.5s ease;
      max-width: 320px;
    }

    .floating-info.hidden {
      opacity: 0;
      transform: translateY(20px);
      pointer-events: none;
    }

    .floating-info h3 {
      color: #00d4ff;
      margin-bottom: 10px;
      font-size: 1.1em;
    }

    .floating-info p {
      color: #00ff41;
      margin: 5px 0;
      font-size: 0.9em;
      word-break: break-all;
    }

    .floating-info .label {
      color: #a0a0a0;
      font-size: 0.8em;
    }

    .stats-row {
      display: flex;
      justify-content: space-between;
      margin-top: 10px;
      padding-top: 10px;
      border-top: 1px solid rgba(0, 255, 65, 0.3);
    }

    .stat-item {
      text-align: center;
    }

    .stat-value {
      font-size: 1.2em;
      color: #00d4ff;
      font-weight: bold;
    }

    @keyframes glow {
      0%, 100% { box-shadow: 0 0 20px rgba(0, 255, 65, 0.3); }
      50% { box-shadow: 0 0 30px rgba(0, 255, 65, 0.6); }
    }

    header {
      animation: glow 3s infinite;
    }

    .loader {
      display: inline-block;
      width: 20px;
      height: 20px;
      border: 3px solid rgba(0, 255, 65, 0.3);
      border-radius: 50%;
      border-top-color: #00ff41;
      animation: spin 1s linear infinite;
    }

    @keyframes spin {
      to { transform: rotate(360deg); }
    }

    @media (max-width: 768px) {
      h1 { font-size: 1.8em; }
      .levels-grid { grid-template-columns: 1fr; }
      .floating-info { max-width: 250px; font-size: 0.85em; }
    }

    /* Giscus 评论区样式 */
    .giscus-section {
      max-width: 1200px;
      margin: 60px auto 40px;
      padding: 30px;
      background: rgba(26, 26, 46, 0.8);
      border: 2px solid #00ff41;
      border-radius: 10px;
      box-shadow: 0 0 20px rgba(0, 255, 65, 0.3);
    }

    .giscus-section h2 {
      color: #00d4ff;
      text-align: center;
      margin-bottom: 20px;
      font-size: 1.8em;
      text-shadow: 0 0 10px #00d4ff;
    }

    .giscus-section p {
      color: #a0a0a0;
      text-align: center;
      margin-bottom: 30px;
      line-height: 1.6;
    }

    /* Giscus iframe 适配 */
    .giscus-section iframe {
      border-radius: 8px;
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1> 网络安全闯关游戏 </h1>
      <p class="subtitle">挑战你的安全技能 | 从简单到专家 | 35个关卡等你攻克</p>

      <div class="typewriter-container">
        <span class="typewriter-text" id="typewriterText"></span>
        <span class="typewriter-cursor"></span>
      </div>

      <div class="progress-bar-container">
        <div class="progress-info">
          <span class="progress-text">通关进度</span>
          <span class="progress-text"><span id="completedCount">0</span> / 35</span>
        </div>
        <div class="progress-bar">
          <div class="progress-fill" id="progressFill" style="width: 0%"></div>
        </div>
        <button class="leaderboard-btn" onclick="openLeaderboard()">查看排行榜</button>
      </div>
    </header>

    <div class="levels-grid" id="levelsGrid">
      <div class="loader"></div>
    </div>

    <!-- 排行榜模态框 -->
    <div id="leaderboardModal" class="modal">
      <div class="modal-content leaderboard-modal">
        <span class="close" onclick="closeLeaderboard()">&times;</span>
        <h2>排行榜</h2>
        <div class="leaderboard-info">
          <p>排行榜每10分钟更新一次</p>
          <p>排名基于完成题目数量和总用时</p>
        </div>
        <div id="currentRankDisplay" class="current-rank"></div>
        <div class="leaderboard-table-container">
          <table class="leaderboard-table">
            <thead>
              <tr>
                <th>排名</th>
                <th>用户ID</th>
                <th>完成数</th>
                <th>总用时</th>
              </tr>
            </thead>
            <tbody id="leaderboardBody">
              <tr><td colspan="4" class="loading">加载中...</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Giscus 评论区 -->
    <div class="giscus-section">
      <h2> 交流讨论区</h2>
      <p>遇到难题？和其他玩家一起讨论解题思路！</p>
      <script src="https://giscus.app/client.js"
        data-repo="inwpu/game"
        data-repo-id="R_kgDOQcbJvw"
        data-category="General"
        data-category-id="DIC_kwDOQcbJv84Cy9_Z"
        data-mapping="pathname"
        data-strict="0"
        data-reactions-enabled="1"
        data-emit-metadata="0"
        data-input-position="bottom"
        data-theme="noborder_dark"
        data-lang="zh-CN"
        crossorigin="anonymous"
        async>
      </script>
    </div>
  </div>

  <!-- 关卡详情弹窗 -->
  <div class="modal" id="levelModal">
    <div class="modal-content">
      <span class="close-btn" onclick="closeModal()">&times;</span>
      <div id="modalContent"></div>
    </div>
  </div>

  <!-- 悬浮信息窗 -->
  <div class="floating-info" id="floatingInfo">
    <h3> 访客信息</h3>
    <p><span class="label">IP地址:</span> <span id="userIp">加载中...</span></p>
    <p><span class="label">设备指纹:</span> <span id="userFingerprint">加载中...</span></p>
    <p><span class="label">有效期:</span> 24小时</p>
    <div class="stats-row">
      <div class="stat-item">
        <div class="label">访客数</div>
        <div class="stat-value" id="totalVisitors">0</div>
      </div>
      <div class="stat-item">
        <div class="label">访问数</div>
        <div class="stat-value" id="totalVisits">0</div>
      </div>
    </div>
  </div>

  <script>
    let currentLevel = null;
    let visitorInfo = null;

    // 本地存储管理
    const STORAGE_KEY = 'ctf_completed_levels';

    function getCompletedLevels() {
      try {
        const data = localStorage.getItem(STORAGE_KEY);
        return data ? JSON.parse(data) : [];
      } catch (error) {
        return [];
      }
    }

    function saveCompletedLevel(levelId) {
      try {
        const completed = getCompletedLevels();
        if (!completed.includes(levelId)) {
          completed.push(levelId);
          localStorage.setItem(STORAGE_KEY, JSON.stringify(completed));
        }
        updateProgress();
      } catch (error) {
        console.error('保存进度失败:', error);
      }
    }

    function isLevelCompleted(levelId) {
      return getCompletedLevels().includes(levelId);
    }

    async function updateProgress() {
      try {
        // 从服务器获取进度
        const response = await fetch('/api/progress');
        const data = await response.json();

        const total = 35;
        const percentage = (data.totalCompleted / total) * 100;

        document.getElementById('completedCount').textContent = data.totalCompleted;
        document.getElementById('progressFill').style.width = percentage + '%';

        return data;
      } catch (error) {
        console.error('获取进度失败:', error);
        // 降级到本地存储
        const completed = getCompletedLevels();
        const total = 35;
        const percentage = (completed.length / total) * 100;

        document.getElementById('completedCount').textContent = completed.length;
        document.getElementById('progressFill').style.width = percentage + '%';
      }
    }

    // 排行榜相关函数
    async function openLeaderboard() {
      const modal = document.getElementById('leaderboardModal');
      modal.style.display = 'block';

      // 加载排行榜数据
      await loadLeaderboard();
    }

    function closeLeaderboard() {
      const modal = document.getElementById('leaderboardModal');
      modal.style.display = 'none';
    }

    async function loadLeaderboard() {
      try {
        const tbody = document.getElementById('leaderboardBody');
        tbody.innerHTML = '<tr><td colspan="4" class="loading">加载中...</td></tr>';

        const response = await fetch('/api/leaderboard');
        const data = await response.json();

        if (!data.ranks || data.ranks.length === 0) {
          tbody.innerHTML = '<tr><td colspan="4" class="loading">暂无排行数据</td></tr>';
          return;
        }

        // 显示当前用户排名
        const currentRankDisplay = document.getElementById('currentRankDisplay');
        if (data.currentUser) {
          currentRankDisplay.innerHTML = \`
            你的排名: 第 \${data.currentUser.rank} 名 |
            已完成: \${data.currentUser.completed}/35 |
            总用时: \${data.currentUser.time}
          \`;
          currentRankDisplay.style.display = 'block';
        } else {
          currentRankDisplay.innerHTML = '完成第一题即可上榜！';
          currentRankDisplay.style.display = 'block';
        }

        // 渲染排行榜
        tbody.innerHTML = data.ranks.map(user => {
          let rankClass = '';
          if (user.rank === 1) rankClass = 'rank-1';
          else if (user.rank === 2) rankClass = 'rank-2';
          else if (user.rank === 3) rankClass = 'rank-3';

          const rowClass = user.isCurrentUser ? 'current-user' : '';

          return \`
            <tr class="\${rowClass}">
              <td class="\${rankClass}">\${user.rank}</td>
              <td>\${user.id}</td>
              <td>\${user.completed}/35</td>
              <td>\${user.time}</td>
            </tr>
          \`;
        }).join('');

      } catch (error) {
        console.error('加载排行榜失败:', error);
        const tbody = document.getElementById('leaderboardBody');
        tbody.innerHTML = '<tr><td colspan="4" class="loading">加载失败，请稍后重试</td></tr>';
      }
    }

    // 10分钟自动刷新排行榜
    let leaderboardRefreshTimer = null;
    function startLeaderboardAutoRefresh() {
      // 清除旧的定时器
      if (leaderboardRefreshTimer) {
        clearInterval(leaderboardRefreshTimer);
      }

      // 设置10分钟刷新一次
      leaderboardRefreshTimer = setInterval(() => {
        const modal = document.getElementById('leaderboardModal');
        if (modal.style.display === 'block') {
          loadLeaderboard();
        }
      }, 10 * 60 * 1000); // 10分钟
    }

    // 打字机文本内容（网络安全知识）
    const typewriterTexts = [
      " SQL注入是OWASP Top 10中排名第一的安全威胁...",
      " XSS攻击可以窃取用户的Cookie和Session...",
      " 使用HTTPS可以防止中间人攻击（MITM）...",
      " CSRF攻击利用用户的登录状态执行恶意操作...",
      " 永远不要在客户端存储敏感信息...",
      " 定期更新依赖库可以避免已知漏洞...",
      " 使用参数化查询可以防止SQL注入...",
      " JWT的payload是Base64编码，任何人都能解码...",
      " 弱密码是最常见的安全隐患之一...",
      " CSP（内容安全策略）可以有效防御XSS攻击..."
    ];

    let currentTextIndex = 0;
    let currentCharIndex = 0;
    let isDeleting = false;

    // 打字机效果
    function typeWriter() {
      const textElement = document.getElementById('typewriterText');
      const currentText = typewriterTexts[currentTextIndex];

      if (!isDeleting) {
        // 打字
        textElement.textContent = currentText.substring(0, currentCharIndex + 1);
        currentCharIndex++;

        if (currentCharIndex === currentText.length) {
          // 打完后暂停
          setTimeout(() => { isDeleting = true; }, 3000);
          setTimeout(typeWriter, 3000);
          return;
        }
      } else {
        // 删除
        textElement.textContent = currentText.substring(0, currentCharIndex - 1);
        currentCharIndex--;

        if (currentCharIndex === 0) {
          isDeleting = false;
          currentTextIndex = (currentTextIndex + 1) % typewriterTexts.length;
        }
      }

      const speed = isDeleting ? 30 : 80;
      setTimeout(typeWriter, speed);
    }

    // 加载访客信息
    async function loadVisitorInfo() {
      try {
        const response = await fetch('/api/visitor');
        visitorInfo = await response.json();
        document.getElementById('userIp').textContent = visitorInfo.ip;
        document.getElementById('userFingerprint').textContent = visitorInfo.fingerprint;
        document.getElementById('totalVisitors').textContent = visitorInfo.totalVisitors || 0;
        document.getElementById('totalVisits').textContent = visitorInfo.totalVisits || 0;

        // 10秒后隐藏悬浮窗
        setTimeout(() => {
          document.getElementById('floatingInfo').classList.add('hidden');
        }, 10000);
      } catch (error) {
        console.error('加载访客信息失败:', error);
      }
    }

    // 加载关卡列表
    async function loadLevels() {
      try {
        const [levelsResponse, progressResponse] = await Promise.all([
          fetch('/api/levels'),
          fetch('/api/progress')
        ]);

        const levels = await levelsResponse.json();
        const progressData = await progressResponse.json();
        const completedLevels = progressData.completed || [];

        const grid = document.getElementById('levelsGrid');
        grid.innerHTML = levels.map(level => {
          const completed = completedLevels.includes(level.id);
          const completedClass = completed ? 'completed' : '';

          let testEnvButton = '';
          if (level.testEnv) {
            const testEnvUrl = typeof level.testEnv === 'string' ?
              \`/test/\${level.testEnv}\` :
              \`/test/\${level.id}\`;
            testEnvButton = \`
              <button class="test-env-btn" onclick="event.stopPropagation(); window.open('\${testEnvUrl}', '_blank')">
                测试环境
              </button>
            \`;
          }

          return \`
            <div class="level-card \${completedClass}" onclick="openLevel(\${level.id})">
              <div class="level-header">
                <span class="level-id">Level \${level.id}</span>
                <span class="difficulty \${level.difficulty}">\${level.difficulty}</span>
              </div>
              <h3 class="level-name">\${level.name}</h3>
              <p class="category"> \${level.category}</p>
              <p class="description">\${level.description}</p>
              \${testEnvButton}
            </div>
          \`;
        }).join('');

        // 更新进度
        await updateProgress();
      } catch (error) {
        console.error('加载关卡失败:', error);
      }
    }

    // 打开关卡详情
    async function openLevel(levelId) {
      try {
        const response = await fetch(\`/api/level/\${levelId}\`);
        currentLevel = await response.json();

        const modal = document.getElementById('levelModal');
        const content = document.getElementById('modalContent');

        let testEnvButton = '';
        if (currentLevel.testEnv) {
          const testEnvUrl = typeof currentLevel.testEnv === 'string' ?
            \`/test/\${currentLevel.testEnv}\` :
            \`/test/\${currentLevel.id}\`;
          testEnvButton = \`
            <button class="test-env-btn-modal" onclick="window.open('\${testEnvUrl}', '_blank')" style="margin-top: 10px;">
              打开测试环境
            </button>
          \`;
        }

        content.innerHTML = \`
          <h2 style="color: #00d4ff; margin-bottom: 20px;">
            Level \${currentLevel.id}: \${currentLevel.name}
          </h2>
          <p style="color: #00ff41; margin-bottom: 10px;">
            <strong>难度:</strong> <span class="difficulty \${currentLevel.difficulty}">\${currentLevel.difficulty}</span>
          </p>
          <p style="color: #00ff41; margin-bottom: 20px;">
            <strong>分类:</strong> \${currentLevel.category}
          </p>
          <p style="color: #a0a0a0; margin-bottom: 20px; line-height: 1.6;">
            \${currentLevel.description}
          </p>
          <div class="hint-box">
            <strong style="color: #00d4ff;"> 提示:</strong><br>
            <span style="color: #00ff41;">\${currentLevel.hint}</span>
          </div>
          \${testEnvButton}
          <div class="input-group">
            <label for="answerInput">请输入你的答案:</label>
            <input type="text" id="answerInput" placeholder="输入答案或flag..."
                   onkeypress="if(event.key==='Enter') submitAnswer()">
          </div>
          <button class="submit-btn" onclick="submitAnswer()"> 提交答案</button>
          <div class="result-box" id="resultBox"></div>
        \`;

        modal.classList.add('active');
      } catch (error) {
        console.error('加载关卡详情失败:', error);
      }
    }

    // 关闭弹窗
    function closeModal() {
      document.getElementById('levelModal').classList.remove('active');
      currentLevel = null;
    }

    // 提交答案
    async function submitAnswer() {
      const answer = document.getElementById('answerInput').value.trim();
      const resultBox = document.getElementById('resultBox');

      if (!answer) {
        resultBox.className = 'result-box error';
        resultBox.innerHTML = ' 请输入答案';
        return;
      }

      try {
        const response = await fetch('/api/submit', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'User-Agent': navigator.userAgent,
            'Cookie': document.cookie,
            'Origin': window.location.origin,
            'Referer': document.referrer || window.location.href
          },
          body: JSON.stringify({
            levelId: currentLevel.id,
            answer: answer
          })
        });

        const result = await response.json();

        if (result.passed) {
          resultBox.className = 'result-box success';
          resultBox.innerHTML = \`
            <strong> \${result.message}</strong>
            <div class="flag"> \${result.flag}</div>
          \`;

          // 重新加载关卡列表以显示完成标记（从服务器获取最新进度）
          setTimeout(() => {
            loadLevels();
          }, 1000);
        } else {
          resultBox.className = 'result-box error';
          resultBox.innerHTML = \`<strong> \${result.message}</strong>\`;
          if (result.hint) {
            resultBox.innerHTML += \`<br><small style="color: #00d4ff;">\${result.hint}</small>\`;
          }
        }
      } catch (error) {
        resultBox.className = 'result-box error';
        resultBox.innerHTML = ' 提交失败，请重试';
        console.error('提交答案失败:', error);
      }
    }

    // 点击弹窗外部关闭
    document.getElementById('levelModal').addEventListener('click', (e) => {
      if (e.target.id === 'levelModal') {
        closeModal();
      }
    });

    // 初始化
    window.addEventListener('DOMContentLoaded', () => {
      loadVisitorInfo();
      loadLevels();
      typeWriter();
      startLeaderboardAutoRefresh(); // 启动排行榜自动刷新
    });
  </script>
</body>
</html>`;

// ==================== 测试环境 HTML ====================

const SQL_LAB_HTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SQL注入测试实验室</title>
  <style>
    body {
      font-family: 'Consolas', monospace;
      background: linear-gradient(135deg, #0a0e27 0%, #1a1a2e 100%);
      color: #00ff41;
      padding: 40px;
      min-height: 100vh;
    }
    .lab-container {
      max-width: 800px;
      margin: 0 auto;
      background: rgba(26, 26, 46, 0.9);
      border: 2px solid #00ff41;
      border-radius: 10px;
      padding: 30px;
      box-shadow: 0 0 30px rgba(0, 255, 65, 0.4);
    }
    h1 {
      color: #00d4ff;
      text-align: center;
      text-shadow: 0 0 10px #00d4ff;
    }
    .login-form {
      margin: 30px 0;
      padding: 20px;
      background: rgba(10, 14, 39, 0.6);
      border-radius: 5px;
    }
    .form-group {
      margin: 15px 0;
    }
    label {
      display: block;
      margin-bottom: 5px;
      color: #00ff41;
    }
    input {
      width: 100%;
      padding: 10px;
      background: #0a0e27;
      border: 2px solid #00ff41;
      border-radius: 5px;
      color: #00ff41;
      font-family: 'Consolas', monospace;
    }
    button {
      width: 100%;
      padding: 12px;
      background: #00ff41;
      color: #0a0e27;
      border: none;
      border-radius: 5px;
      font-weight: bold;
      cursor: pointer;
      margin-top: 10px;
    }
    .hint-box {
      background: rgba(0, 212, 255, 0.1);
      border-left: 4px solid #00d4ff;
      padding: 15px;
      margin: 20px 0;
      border-radius: 5px;
    }
    .result {
      margin-top: 20px;
      padding: 15px;
      border-radius: 5px;
      display: none;
    }
    .result.show { display: block; }
    .success { background: rgba(0, 255, 65, 0.2); border: 2px solid #00ff41; }
    .error { background: rgba(255, 68, 68, 0.2); border: 2px solid #ff4444; color: #ff4444; }
    .query-display {
      background: #0a0e27;
      padding: 15px;
      border-radius: 5px;
      margin: 15px 0;
      border: 1px solid #00ff41;
      font-family: 'Courier New', monospace;
      word-break: break-all;
    }
  </style>
</head>
<body>
  <div class="lab-container">
    <h1>SQL注入测试实验室</h1>
    <p style="text-align: center; color: #a0a0a0;">Level 4 - 实践环境</p>

    <div class="hint-box">
      <strong style="color: #00d4ff;">任务目标：</strong><br>
      尝试绕过登录验证，找出正确的 SQL 注入 payload
    </div>

    <div class="login-form">
      <h3 style="color: #00ff41;">模拟登录系统</h3>
      <div class="form-group">
        <label>用户名:</label>
        <input type="text" id="username" placeholder="输入用户名">
      </div>
      <div class="form-group">
        <label>密码:</label>
        <input type="password" id="password" placeholder="输入密码">
      </div>
      <button onclick="attemptLogin()">登录</button>
    </div>

    <div id="queryDisplay" class="query-display" style="display: none;">
      <strong>执行的SQL查询：</strong><br>
      <span id="sqlQuery"></span>
    </div>

    <div id="result" class="result"></div>

    <div class="hint-box" style="margin-top: 30px;">
      <strong style="color: #00d4ff;">提示：</strong><br>
      - 后端SQL查询：SELECT * FROM users WHERE username='...' AND password='...'<br>
      - 思考如何闭合引号并注释掉后面的密码检查<br>
      - 成功绕过后，将你的 payload 提交到 Level 4
    </div>
  </div>

  <script>
    function attemptLogin() {
      const username = document.getElementById('username').value;
      const password = document.getElementById('password').value;
      const resultDiv = document.getElementById('result');
      const queryDisplay = document.getElementById('queryDisplay');
      const sqlQuery = document.getElementById('sqlQuery');

      // 构造SQL查询（模拟）
      const query = \`SELECT * FROM users WHERE username='\${username}' AND password='\${password}'\`;

      queryDisplay.style.display = 'block';
      sqlQuery.textContent = query;

      // 检测SQL注入
      if (username.includes("' OR '1'='1") || username.includes("' OR 1=1") ||
          username.includes("admin' --") || username.includes("admin'--")) {
        resultDiv.className = 'result success show';
        resultDiv.innerHTML = \`
          <strong>登录成功！管理员权限已获取</strong><br><br>
          检测到 SQL 注入！你的 payload: <code>\${username}</code><br>
          现在将这个 payload 提交到 Level 4 获取 flag
        \`;
      } else {
        resultDiv.className = 'result error show';
        resultDiv.innerHTML = '登录失败：用户名或密码错误';
      }
    }
  </script>
</body>
</html>`;

const XSS_LAB_HTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>XSS测试实验室</title>
  <style>
    body {
      font-family: 'Consolas', monospace;
      background: linear-gradient(135deg, #0a0e27 0%, #1a1a2e 100%);
      color: #00ff41;
      padding: 40px;
      min-height: 100vh;
    }
    .lab-container {
      max-width: 800px;
      margin: 0 auto;
      background: rgba(26, 26, 46, 0.9);
      border: 2px solid #00ff41;
      border-radius: 10px;
      padding: 30px;
      box-shadow: 0 0 30px rgba(0, 255, 65, 0.4);
    }
    h1 {
      color: #00d4ff;
      text-align: center;
      text-shadow: 0 0 10px #00d4ff;
    }
    .input-area {
      margin: 30px 0;
    }
    textarea {
      width: 100%;
      min-height: 100px;
      padding: 10px;
      background: #0a0e27;
      border: 2px solid #00ff41;
      border-radius: 5px;
      color: #00ff41;
      font-family: 'Consolas', monospace;
      resize: vertical;
    }
    button {
      width: 100%;
      padding: 12px;
      background: #00ff41;
      color: #0a0e27;
      border: none;
      border-radius: 5px;
      font-weight: bold;
      cursor: pointer;
      margin-top: 10px;
    }
    .hint-box {
      background: rgba(0, 212, 255, 0.1);
      border-left: 4px solid #00d4ff;
      padding: 15px;
      margin: 20px 0;
      border-radius: 5px;
    }
    .output-area {
      margin: 20px 0;
      padding: 15px;
      background: rgba(10, 14, 39, 0.6);
      border: 2px solid #ffa500;
      border-radius: 5px;
      min-height: 60px;
    }
    .dangerous {
      color: #ff4444;
      font-weight: bold;
    }
    .safe {
      color: #00ff41;
    }
  </style>
</head>
<body>
  <div class="lab-container">
    <h1>XSS 测试实验室</h1>
    <p style="text-align: center; color: #a0a0a0;">Level 8 - 实践环境</p>

    <div class="hint-box">
      <strong style="color: #00d4ff;">任务目标：</strong><br>
      构造一个 XSS payload，能够执行 JavaScript 代码
    </div>

    <div class="input-area">
      <h3 style="color: #00ff41;">用户评论区（漏洞模拟）</h3>
      <textarea id="userInput" placeholder="在这里输入你的评论..."></textarea>
      <button onclick="submitComment()">提交评论</button>
      <button onclick="submitSafe()" style="background: #00d4ff;">提交评论（安全模式）</button>
    </div>

    <div class="output-area">
      <h4 style="color: #00ff41;">评论显示区：</h4>
      <div id="commentDisplay" style="margin-top: 10px;"></div>
    </div>

    <div id="result" style="margin-top: 20px;"></div>

    <div class="hint-box" style="margin-top: 30px;">
      <strong style="color: #00d4ff;">XSS Payload 示例：</strong><br>
      - &lt;script&gt;alert(1)&lt;/script&gt;<br>
      - &lt;img src=x onerror=alert(1)&gt;<br>
      - &lt;svg onload=alert(1)&gt;<br>
      - 成功触发弹窗后，将 payload 提交到 Level 8
    </div>
  </div>

  <script>
    let xssDetected = false;

    function submitComment() {
      const input = document.getElementById('userInput').value;
      const display = document.getElementById('commentDisplay');
      const resultDiv = document.getElementById('result');

      // 不安全的渲染（故意的漏洞）
      display.innerHTML = '<div style="color: #a0a0a0;">' + input + '</div>';

      // 检测XSS
      if (input.includes('<script>') || input.includes('onerror=') ||
          input.includes('onload=') || input.includes('javascript:')) {
        xssDetected = true;
        resultDiv.innerHTML = \`
          <div class="dangerous" style="padding: 15px; background: rgba(255,68,68,0.2); border-radius: 5px;">
            XSS 漏洞检测成功！<br>
            你的 payload: <code>\${input}</code><br><br>
            现在将这个 payload 提交到 Level 8 获取 flag
          </div>
        \`;
      }
    }

    function submitSafe() {
      const input = document.getElementById('userInput').value;
      const display = document.getElementById('commentDisplay');
      const resultDiv = document.getElementById('result');

      // 安全的渲染（HTML转义）
      const escaped = input
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;');

      display.innerHTML = '<div style="color: #00ff41;">' + escaped + '</div>';
      resultDiv.innerHTML = \`
        <div class="safe" style="padding: 15px; background: rgba(0,255,65,0.1); border-radius: 5px;">
          安全渲染成功！所有HTML标签已被转义<br>
          这就是防御XSS的正确方法
        </div>
      \`;
    }

    // 覆盖 alert 以显示友好提示
    window.alert = function(msg) {
      const resultDiv = document.getElementById('result');
      resultDiv.innerHTML = \`
        <div style="padding: 20px; background: rgba(255,165,0,0.2); border: 2px solid #ffa500; border-radius: 5px; text-align: center;">
          <h2 style="color: #ffa500;">XSS 触发成功！</h2>
          <p>原始弹窗内容: \${msg}</p>
          <p style="color: #00ff41;">恭喜！你成功执行了 XSS 攻击</p>
        </div>
      \`;
    };
  </script>
</body>
</html>`;
