//
//  main.m
//  TestCMD3
//
//  Created by IosBX on 2025/11/28.
//

#import <Foundation/Foundation.h>

int add(int a,int b) {
    return a + b;
}

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        int input = 0;
        printf("请输入数字: ");
        scanf("%d", &input);
        
        if (input == 1) {
            int result = add(1, 1);
            NSLog(@"1 + 1 = %d", result);
        }
    }
    return 0;
}